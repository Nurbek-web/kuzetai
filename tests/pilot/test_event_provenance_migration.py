from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MIGRATION = REPO_ROOT / "migrations/versions/0006_event_provenance.py"


def test_migration_is_additive_fenced_and_preserves_v1_candidate_rows() -> None:
    source = MIGRATION.read_text(encoding="utf-8")

    for table in (
        "site_config_revisions",
        "camera_ruleset_revisions",
        "camera_rule_revisions",
        "active_pilot_configurations",
        "runtime_writer_authorities",
        "runtime_writer_sessions",
        "camera_epoch_authorities",
        "legacy_candidate_imports",
        "candidate_event_provenance",
    ):
        assert f'"{table}"' in source
    assert "drop_table(\"candidate_events\")" not in source
    assert "runtime_writer_generation" in source
    assert "configuration_activation_generation" in source
    assert "trg_candidate_provenance_fence" in source


def test_migration_keeps_runtime_role_least_privilege_and_optional() -> None:
    source = MIGRATION.read_text(encoding="utf-8")

    assert "IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kuzet_runtime')" in source
    assert "CREATE FUNCTION pilot_ingest_candidate" in source
    assert "SECURITY DEFINER" in source
    assert "GRANT EXECUTE ON FUNCTION pilot_ingest_candidate" in source
    assert "GRANT SELECT, INSERT ON TABLE candidate_events" not in source
    assert (
        "GRANT SELECT, INSERT ON TABLE candidate_event_provenance TO kuzet_runtime"
        not in source
    )
    assert "REVOKE INSERT, UPDATE, DELETE ON TABLE candidate_events" in source
    assert (
        "REVOKE INSERT, UPDATE, DELETE ON TABLE candidate_event_provenance"
        in source
    )
    assert "GRANT ALL" not in source
    assert "CREATE ROLE kuzet_runtime" not in source
