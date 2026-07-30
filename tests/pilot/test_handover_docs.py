from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs" / "pilot"


@pytest.mark.parametrize(
    ("filename", "required"),
    (
        (
            "operator_runbook.md",
            (
                "human confirmation",
                "candidate",
                "source outage",
                "evidence pending",
                "notification failure",
                "camera replacement",
            ),
        ),
        (
            "incident_response.md",
            (
                "No automatic police",
                "containment",
                "audit",
                "evidence",
                "notification",
            ),
        ),
        (
            "deployment_runbook.md",
            (
                "ready_to_start.md",
                "TARGET_ACCEPTANCE.md",
                "NETWORK_POLICY.md",
                "AUDIT_RETENTION.md",
                "fresh target",
            ),
        ),
        (
            "model_register.md",
            (
                "rights",
                "artifact SHA-256",
                "engine SHA-256",
                "shadow",
                "PENDING",
            ),
        ),
        (
            "known_limits.md",
            (
                "not production-ready",
                "customer NVR",
                "X-CLIP",
                "OWLv2",
                "entrance-only",
                "lawful gallery",
            ),
        ),
        (
            "handover_manifest.md",
            (
                "container digest",
                "configuration hash",
                "migration revision",
                "gate report",
                "PENDING",
                "named operator",
            ),
        ),
    ),
)
def test_handover_document_has_required_safety_content(
    filename: str,
    required: tuple[str, ...],
) -> None:
    content = (DOCS / filename).read_text()

    for phrase in required:
        assert phrase.casefold() in content.casefold(), (filename, phrase)
    assert "production-ready" not in content.casefold() or (
        "not production-ready" in content.casefold()
    )


def test_readme_separates_investor_demo_from_unvalidated_pilot() -> None:
    content = (ROOT / "README.md").read_text()

    for phrase in (
        "Investor MVP",
        "Controlled-pilot runtime",
        "not a validated 20-camera runtime",
        "protector/pilot/",
        "human confirmation",
        "customer NVR",
    ):
        assert phrase.casefold() in content.casefold()


def test_runbooks_link_existing_authoritative_gates_instead_of_replacing_them() -> None:
    deployment = (DOCS / "deployment_runbook.md").read_text()
    expected_links = (
        "../../docs/pilot/ready_to_start.md",
        "../../deploy/pilot/TARGET_ACCEPTANCE.md",
        "../../deploy/pilot/NETWORK_POLICY.md",
        "../../deploy/pilot/AUDIT_RETENTION.md",
    )

    for target in expected_links:
        assert target in deployment
        assert (DOCS / target).resolve().is_file()


def test_operator_runbook_has_actionable_pending_support_roster_and_drills() -> None:
    operator = (DOCS / "operator_runbook.md").read_text().casefold()

    for phrase in (
        "customer site security contact",
        "customer privacy/security contact",
        "kuzet technical incident contact",
        "must be completed before activation",
        "confirmed",
        "rejected",
        "source-outage",
        "evidence-pending",
        "notification-failure",
    ):
        assert phrase in operator


def test_deployment_runbook_names_real_migration_backup_and_restore_entrypoints() -> None:
    deployment = (DOCS / "deployment_runbook.md").read_text()

    for path in (
        "scripts/pilot/migrate.py",
        "scripts/pilot/backup.sh",
        "scripts/pilot/restore.sh",
    ):
        assert path in deployment
        assert (ROOT / path).is_file()
    for phrase in (
        "credential rotation",
        "rollback",
        "PILOT_BACKUP_TARGET",
        "PILOT_RESTORE_SOURCE",
        "verified_fresh_target_restore",
    ):
        assert phrase.casefold() in deployment.casefold()


def test_handover_manifest_inventory_covers_every_deployed_image_family() -> None:
    manifest = (DOCS / "handover_manifest.md").read_text().casefold()

    for image_family in (
        "deepstream runtime",
        "api/controller",
        "operations image",
        "postgres",
        "nginx tls proxy",
        "prometheus",
    ):
        assert image_family in manifest
