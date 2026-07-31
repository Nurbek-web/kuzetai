from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

from protector.pilot.api.preview_production import (
    PreviewProductionConfigurationError,
    build_reviewed_preview_provider,
    create_configured_preview_provider,
)
from protector.pilot.config import SiteConfig
from protector.pilot.gates import site_config_sha256
from protector.pilot.storage.preview import ProductionPreviewProvider

ROOT = Path(__file__).resolve().parents[2]


class _Repository:
    def __init__(self, active_digest: str) -> None:
        self.active_digest = active_digest
        self.lookups: list[str] = []

    def get_active_site_config_sha256(self, *, site_id: str) -> str:
        self.lookups.append(site_id)
        return self.active_digest


class _ClientFactory:
    def __init__(
        self,
        *,
        versioning_status: str = "Enabled",
        lifecycle_prefix: str = "pilot-evidence/site-1/previews/",
        expiration_days: int = 30,
        noncurrent_days: int = 1,
        newer_noncurrent_versions: int | None = None,
        narrowed_filter: bool = False,
        expiration_extra: bool = False,
        additional_rule: dict[str, object] | None = None,
    ) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.lifecycle_calls: list[tuple[str, str]] = []
        self.versioning_status = versioning_status
        self.lifecycle_prefix = lifecycle_prefix
        self.expiration_days = expiration_days
        self.noncurrent_days = noncurrent_days
        self.newer_noncurrent_versions = newer_noncurrent_versions
        self.narrowed_filter = narrowed_filter
        self.expiration_extra = expiration_extra
        self.additional_rule = additional_rule

    def __call__(self, service: str, **kwargs: Any) -> object:
        self.calls.append((service, kwargs))
        return self

    def get_bucket_versioning(self, *, Bucket: str) -> dict[str, str]:
        self.lifecycle_calls.append(("versioning", Bucket))
        return {"Status": self.versioning_status}

    def get_bucket_lifecycle_configuration(
        self,
        *,
        Bucket: str,
    ) -> dict[str, object]:
        self.lifecycle_calls.append(("lifecycle", Bucket))
        filter_value: dict[str, object] = {
            "Prefix": self.lifecycle_prefix,
        }
        if self.narrowed_filter:
            filter_value["Tag"] = {"Key": "scope", "Value": "narrowed"}
        expiration: dict[str, object] = {"Days": self.expiration_days}
        if self.expiration_extra:
            expiration["ExpiredObjectDeleteMarker"] = True
        noncurrent: dict[str, object] = {
            "NoncurrentDays": self.noncurrent_days,
        }
        if self.newer_noncurrent_versions is not None:
            noncurrent["NewerNoncurrentVersions"] = (
                self.newer_noncurrent_versions
            )
        rules = [
            {
                "Status": "Enabled",
                "Filter": filter_value,
                "Expiration": expiration,
                "NoncurrentVersionExpiration": noncurrent,
            }
        ]
        if self.additional_rule is not None:
            rules.append(self.additional_rule)
        return {"Rules": rules}


def _client_configuration() -> SimpleNamespace:
    return SimpleNamespace(
        connect_timeout=3,
        read_timeout=10,
        retries={
            "mode": "standard",
            "total_max_attempts": 3,
        },
        signature_version="s3v4",
        tcp_keepalive=True,
    )


def _reviewed_config(tmp_path: Path) -> tuple[Path, str, str]:
    template = yaml.safe_load(
        (ROOT / "configs/pilot.example.yaml").read_bytes()
    )
    expanded = json.loads(json.dumps(template))
    expanded["storage"]["evidence_prefix"] = "pilot-evidence/site-1"
    payload = yaml.safe_dump(expanded, sort_keys=False)
    path = tmp_path / "site.yaml"
    path.write_text(payload)
    raw_digest = hashlib.sha256(payload.encode()).hexdigest()
    canonical_digest = site_config_sha256(SiteConfig.model_validate(expanded))
    assert raw_digest != canonical_digest
    return path, raw_digest, canonical_digest


def _secret(tmp_path: Path, name: str, value: str) -> Path:
    path = tmp_path / name
    path.write_text(value)
    path.chmod(0o600)
    return path


def test_reviewed_preview_provider_uses_active_config_and_distinct_read_credentials(
    tmp_path: Path,
) -> None:
    config_path, digest, canonical_digest = _reviewed_config(tmp_path)
    repository = _Repository(canonical_digest)
    client_factory = _ClientFactory(
        additional_rule={
            "Status": "Enabled",
            "Filter": {"Prefix": "pilot-evidence/site-1/"},
            "Expiration": {"Days": 30},
            "NoncurrentVersionExpiration": {"NoncurrentDays": 1},
        }
    )

    provider = build_reviewed_preview_provider(
        repository=repository,
        site_id="site-1",
        site_config_path=config_path,
        expected_site_config_sha256=digest,
        region="kz-almaty-1",
        access_key_file=_secret(tmp_path, "preview-access", "preview-reader"),
        secret_key_file=_secret(tmp_path, "preview-secret", "preview-password"),
        client_factory=client_factory,
        clock=lambda: datetime(2026, 7, 31, 12, 0, tzinfo=UTC),
        max_preview_bytes=16 * 1024 * 1024,
        client_configuration=_client_configuration(),
    )

    assert isinstance(provider, ProductionPreviewProvider)
    assert repository.lookups == ["site-1"]
    assert len(client_factory.calls) == 1
    service, arguments = client_factory.calls[0]
    assert service == "s3"
    assert arguments == {
        "endpoint_url": "https://object-storage.customer.example",
        "region_name": "kz-almaty-1",
        "aws_access_key_id": "preview-reader",
        "aws_secret_access_key": "preview-password",
        "config": arguments["config"],
    }
    assert arguments["config"].connect_timeout == 3
    assert arguments["config"].read_timeout == 10
    assert arguments["config"].retries == {
        "mode": "standard",
        "total_max_attempts": 3,
    }
    assert arguments["config"].signature_version == "s3v4"
    assert arguments["config"].tcp_keepalive is True
    assert client_factory.lifecycle_calls == [
        ("versioning", "kuzet-pilot-evidence"),
        ("lifecycle", "kuzet-pilot-evidence"),
    ]


@pytest.mark.parametrize(
    "active_digest",
    (
        "b" * 64,
        "",
    ),
)
def test_reviewed_preview_provider_rejects_inactive_or_missing_config_identity(
    tmp_path: Path,
    active_digest: str,
) -> None:
    config_path, digest, _ = _reviewed_config(tmp_path)
    client_factory = _ClientFactory()

    with pytest.raises(
        PreviewProductionConfigurationError,
        match="active reviewed configuration",
    ):
        build_reviewed_preview_provider(
            repository=_Repository(active_digest),
            site_id="site-1",
            site_config_path=config_path,
            expected_site_config_sha256=digest,
            region="kz-almaty-1",
            access_key_file=_secret(tmp_path, "preview-access", "preview-reader"),
            secret_key_file=_secret(tmp_path, "preview-secret", "preview-password"),
            client_factory=client_factory,
            clock=lambda: datetime.now(UTC),
            max_preview_bytes=1024,
            client_configuration=_client_configuration(),
        )

    assert client_factory.calls == []


def test_reviewed_preview_provider_rejects_config_byte_digest_mismatch_before_client(
    tmp_path: Path,
) -> None:
    config_path, digest, canonical_digest = _reviewed_config(tmp_path)
    client_factory = _ClientFactory()

    with pytest.raises(
        PreviewProductionConfigurationError,
        match="digest",
    ):
        build_reviewed_preview_provider(
            repository=_Repository(canonical_digest),
            site_id="site-1",
            site_config_path=config_path,
            expected_site_config_sha256="c" * 64,
            region="kz-almaty-1",
            access_key_file=_secret(tmp_path, "preview-access", "preview-reader"),
            secret_key_file=_secret(tmp_path, "preview-secret", "preview-password"),
            client_factory=client_factory,
            clock=lambda: datetime.now(UTC),
            max_preview_bytes=1024,
            client_configuration=_client_configuration(),
        )

    assert client_factory.calls == []


@pytest.mark.parametrize(
    "malicious_suffix",
    (
        "\nstorage:\n  evidence_prefix: attacker-prefix/site-1\n",
        "\nreviewed_copy: &reviewed_copy\n  enabled: true\n",
        "\nreviewed_copy: !unsafe value\n",
    ),
)
def test_reviewed_preview_provider_rejects_ambiguous_yaml_before_client(
    tmp_path: Path,
    malicious_suffix: str,
) -> None:
    config_path, _, _ = _reviewed_config(tmp_path)
    payload = config_path.read_text() + malicious_suffix
    config_path.write_text(payload)
    digest = hashlib.sha256(payload.encode()).hexdigest()
    client_factory = _ClientFactory()

    with pytest.raises(
        PreviewProductionConfigurationError,
        match="configuration is invalid",
    ):
        build_reviewed_preview_provider(
            repository=_Repository(digest),
            site_id="site-1",
            site_config_path=config_path,
            expected_site_config_sha256=digest,
            region="kz-almaty-1",
            access_key_file=_secret(
                tmp_path,
                "preview-access",
                "preview-reader",
            ),
            secret_key_file=_secret(
                tmp_path,
                "preview-secret",
                "preview-password",
            ),
            client_factory=client_factory,
            clock=lambda: datetime.now(UTC),
            max_preview_bytes=1024,
            client_configuration=_client_configuration(),
        )

    assert client_factory.calls == []


@pytest.mark.parametrize(
    "client_factory",
    (
        _ClientFactory(versioning_status="Suspended"),
        _ClientFactory(expiration_days=1),
        _ClientFactory(noncurrent_days=2),
        _ClientFactory(expiration_days=31),
        _ClientFactory(noncurrent_days=31),
        _ClientFactory(newer_noncurrent_versions=1),
        _ClientFactory(narrowed_filter=True),
        _ClientFactory(expiration_extra=True),
        _ClientFactory(
            additional_rule={
                "Status": "Enabled",
                "Expiration": {"Days": 1},
            }
        ),
        _ClientFactory(
            additional_rule={
                "Status": "Enabled",
                "Filter": {"Prefix": "pilot-evidence/site-1/"},
                "Expiration": {"Days": 1},
            }
        ),
        _ClientFactory(
            additional_rule={
                "Status": "Enabled",
                "Filter": {
                    "Prefix": "pilot-evidence/site-1/previews/camera-01/",
                },
                "Expiration": {"Days": 1},
            }
        ),
        _ClientFactory(
            additional_rule={
                "Status": "Enabled",
                "Filter": {
                    "Tag": {"Key": "scope", "Value": "narrowed"},
                },
                "Expiration": {"Days": 1},
            }
        ),
        _ClientFactory(lifecycle_prefix="pilot-evidence/site-2/previews/"),
    ),
)
def test_reviewed_preview_provider_requires_bounded_version_lifecycle(
    tmp_path: Path,
    client_factory: _ClientFactory,
) -> None:
    config_path, digest, canonical_digest = _reviewed_config(tmp_path)

    with pytest.raises(
        PreviewProductionConfigurationError,
        match="lifecycle attestation",
    ):
        build_reviewed_preview_provider(
            repository=_Repository(canonical_digest),
            site_id="site-1",
            site_config_path=config_path,
            expected_site_config_sha256=digest,
            region="kz-almaty-1",
            access_key_file=_secret(
                tmp_path,
                "preview-access",
                "preview-reader",
            ),
            secret_key_file=_secret(
                tmp_path,
                "preview-secret",
                "preview-password",
            ),
            client_factory=client_factory,
            clock=lambda: datetime.now(UTC),
            max_preview_bytes=1024,
            client_configuration=_client_configuration(),
        )


@pytest.mark.parametrize(
    "configuration",
    (
        SimpleNamespace(
            connect_timeout=0,
            read_timeout=10,
            retries={"mode": "standard", "total_max_attempts": 3},
            signature_version="s3v4",
            tcp_keepalive=True,
        ),
        SimpleNamespace(
            connect_timeout=3,
            read_timeout=10,
            retries={"mode": "adaptive", "total_max_attempts": 3},
            signature_version="s3v4",
            tcp_keepalive=True,
        ),
        SimpleNamespace(
            connect_timeout=3,
            read_timeout=10,
            retries={"mode": "standard", "total_max_attempts": 4},
            signature_version="s3v4",
            tcp_keepalive=True,
        ),
    ),
)
def test_reviewed_preview_provider_rejects_unbounded_client_configuration(
    tmp_path: Path,
    configuration: SimpleNamespace,
) -> None:
    config_path, digest, canonical_digest = _reviewed_config(tmp_path)
    client_factory = _ClientFactory()

    with pytest.raises(
        PreviewProductionConfigurationError,
        match="client bounds",
    ):
        build_reviewed_preview_provider(
            repository=_Repository(canonical_digest),
            site_id="site-1",
            site_config_path=config_path,
            expected_site_config_sha256=digest,
            region="kz-almaty-1",
            access_key_file=_secret(
                tmp_path,
                "preview-access",
                "preview-reader",
            ),
            secret_key_file=_secret(
                tmp_path,
                "preview-secret",
                "preview-password",
            ),
            client_factory=client_factory,
            clock=lambda: datetime.now(UTC),
            max_preview_bytes=1024,
            client_configuration=configuration,
        )

    assert client_factory.calls == []


def test_reviewed_preview_provider_rejects_symlinked_read_secret(
    tmp_path: Path,
) -> None:
    config_path, digest, canonical_digest = _reviewed_config(tmp_path)
    target = _secret(tmp_path, "real-secret", "preview-reader")
    linked = tmp_path / "preview-access"
    linked.symlink_to(target)

    with pytest.raises(
        PreviewProductionConfigurationError,
        match="credential",
    ):
        build_reviewed_preview_provider(
            repository=_Repository(canonical_digest),
            site_id="site-1",
            site_config_path=config_path,
            expected_site_config_sha256=digest,
            region="kz-almaty-1",
            access_key_file=linked,
            secret_key_file=_secret(tmp_path, "preview-secret", "preview-password"),
            client_factory=_ClientFactory(),
            clock=lambda: datetime.now(UTC),
            max_preview_bytes=1024,
            client_configuration=_client_configuration(),
        )


def test_preview_provider_is_absent_when_runtime_overlay_is_not_selected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "PILOT_SITE_CONFIG_PATH",
        "PILOT_SITE_CONFIG_SHA256",
        "PILOT_PREVIEW_OBJECT_STORE_REGION",
        "PILOT_PREVIEW_OBJECT_STORE_ACCESS_KEY_FILE",
        "PILOT_PREVIEW_OBJECT_STORE_SECRET_KEY_FILE",
    ):
        monkeypatch.delenv(name, raising=False)

    assert (
        create_configured_preview_provider(
            repository=_Repository("a" * 64),
            site_id="site-1",
            clock=lambda: datetime.now(UTC),
        )
        is None
    )


def test_partial_preview_overlay_configuration_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "PILOT_SITE_CONFIG_PATH",
        "PILOT_SITE_CONFIG_SHA256",
        "PILOT_PREVIEW_OBJECT_STORE_REGION",
        "PILOT_PREVIEW_OBJECT_STORE_ACCESS_KEY_FILE",
        "PILOT_PREVIEW_OBJECT_STORE_SECRET_KEY_FILE",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("PILOT_SITE_CONFIG_PATH", "/run/config/site.yaml")

    with pytest.raises(
        PreviewProductionConfigurationError,
        match="incomplete",
    ):
        create_configured_preview_provider(
            repository=_Repository("a" * 64),
            site_id="site-1",
            clock=lambda: datetime.now(UTC),
        )
