from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

import pytest

from protector.pilot.config import load_site_config
from protector.pilot.gates import site_config_sha256
from protector.pilot import retention_service


REPO_ROOT = Path(__file__).parents[2]
NOW = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)


class _Repository:
    def __init__(self, active_digest: str = "a" * 64) -> None:
        self.active_digest = active_digest
        self.active_lookups: list[str] = []

    def get_active_site_config_sha256(self, *, site_id: str) -> str:
        self.active_lookups.append(site_id)
        return self.active_digest

    def claim_preview_receipts_for_retention(
        self,
        **_: object,
    ) -> tuple[object, ...]:
        return ()

    def retire_expired_preview_intents(self, **_: object) -> int:
        return 0

    def prune_preview_access_receipts(self, **_: object) -> int:
        return 0


class _PreviewStore:
    pass


def _arguments() -> object:
    return retention_service.parse_retention_arguments(
        (
            "--database-url-secret=/run/secrets/database",
            "--access-key-secret=/run/secrets/access",
            "--secret-key-secret=/run/secrets/secret",
            "--archive-age-recipient=/run/secrets/age",
            "--archive-signing-private-key=/run/secrets/signing-private",
            "--archive-signing-public-key=/run/secrets/signing-public",
            "--archive-signing-key-id=archive-key-1",
            "--archive-prefix=audit/site-1",
            "--site-id=site-1",
            "--site-config=/run/config/site.yaml",
            f"--site-config-sha256={'a' * 64}",
            "--object-store-region=kz-almaty-1",
            "--preview-batch-size=25",
            "--preview-publication-grace-seconds=600",
        )
    )


def test_preview_retention_composition_uses_reviewed_finite_policy() -> None:
    site = load_site_config(REPO_ROOT / "configs/pilot.example.yaml")

    registered, orphan = retention_service.build_preview_retention_coordinators(
        arguments=_arguments(),
        site=site,
        repository=_Repository(),
        preview_store=_PreviewStore(),
        clock=lambda: NOW,
    )

    assert registered.site_id == "site-1"
    assert registered.retention_days == 30
    assert registered.metadata_retention_days == 365
    assert registered.batch_size == 25
    assert orphan.site_id == "site-1"
    assert orphan.batch_size == 25


def test_retention_requires_canonical_active_config_before_object_store() -> None:
    site = load_site_config(REPO_ROOT / "configs/pilot.example.yaml")
    canonical_digest = site_config_sha256(site)
    repository = _Repository(canonical_digest)

    retention_service._require_active_reviewed_configuration(
        repository=repository,  # type: ignore[arg-type]
        site_id="site-1",
        site=site,
    )

    assert repository.active_lookups == ["site-1"]
    with pytest.raises(
        RuntimeError,
        match="not the active reviewed revision",
    ):
        retention_service._require_active_reviewed_configuration(
            repository=_Repository("f" * 64),  # type: ignore[arg-type]
            site_id="site-1",
            site=site,
        )


@pytest.mark.parametrize(
    ("name", "value"),
    (
        ("--preview-batch-size", "0"),
        ("--preview-batch-size", "1001"),
        ("--preview-publication-grace-seconds", "59"),
        ("--preview-publication-grace-seconds", "86401"),
    ),
)
def test_preview_retention_cli_rejects_unbounded_values(
    name: str,
    value: str,
) -> None:
    command = [
        f"{name}={value}" if item.split("=", 1)[0] == name else item
        for item in (
            "--database-url-secret=/run/secrets/database",
            "--access-key-secret=/run/secrets/access",
            "--secret-key-secret=/run/secrets/secret",
            "--archive-age-recipient=/run/secrets/age",
            "--archive-signing-private-key=/run/secrets/signing-private",
            "--archive-signing-public-key=/run/secrets/signing-public",
            "--archive-signing-key-id=archive-key-1",
            "--archive-prefix=audit/site-1",
            "--site-id=site-1",
            "--site-config=/run/config/site.yaml",
            f"--site-config-sha256={'a' * 64}",
            "--object-store-region=kz-almaty-1",
            "--preview-batch-size=25",
            "--preview-publication-grace-seconds=600",
        )
    ]

    with pytest.raises(SystemExit) as exit_status:
        retention_service.parse_retention_arguments(command)

    assert exit_status.value.code == 2


def test_preview_orphan_cursor_must_be_complete_and_advance() -> None:
    assert retention_service._advance_preview_cursor(
        previous=(None, None),
        next_cursor=("next-key", "next-version"),
    ) == ("next-key", "next-version")
    assert retention_service._advance_preview_cursor(
        previous=("last-key", "last-version"),
        next_cursor=(None, None),
    ) == (None, None)

    with pytest.raises(RuntimeError, match="did not advance"):
        retention_service._advance_preview_cursor(
            previous=("next-key", "next-version"),
            next_cursor=("next-key", "next-version"),
        )
    with pytest.raises(RuntimeError, match="incomplete"):
        retention_service._advance_preview_cursor(
            previous=(None, None),
            next_cursor=("next-key", None),
        )


def test_reviewed_retention_config_uses_strict_single_read_yaml(
    tmp_path: Path,
) -> None:
    payload = (
        REPO_ROOT / "configs/pilot.example.yaml"
    ).read_bytes() + b"\nqueues:\n  decode: 1\n"
    path = tmp_path / "site.yaml"
    path.write_bytes(payload)

    with pytest.raises(ValueError, match="duplicate YAML mapping key"):
        retention_service._reviewed_config(
            path.resolve(),
            hashlib.sha256(payload).hexdigest(),
        )


def test_reviewed_retention_config_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "site-target.yaml"
    payload = (REPO_ROOT / "configs/pilot.example.yaml").read_bytes()
    target.write_bytes(payload)
    alias = tmp_path / "site.yaml"
    alias.symlink_to(target)

    with pytest.raises(RuntimeError, match="unavailable"):
        retention_service._reviewed_config(
            alias.absolute(),
            hashlib.sha256(payload).hexdigest(),
        )
