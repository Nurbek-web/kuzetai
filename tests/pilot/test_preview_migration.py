from __future__ import annotations

import ast
from pathlib import Path

from protector.pilot.storage import models

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "migrations/versions/0007_preview_persistence.py"


def _model_columns(table_name: str) -> set[str]:
    return {column.name for column in models.Base.metadata.tables[table_name].columns}


def _migration_columns() -> dict[str, set[str]]:
    tree = ast.parse(MIGRATION.read_text())
    result: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if (
            not isinstance(node, ast.Call)
            or not isinstance(node.func, ast.Attribute)
            or node.func.attr != "create_table"
            or not node.args
            or not isinstance(node.args[0], ast.Constant)
        ):
            continue
        table_name = node.args[0].value
        columns: set[str] = set()
        for argument in node.args[1:]:
            if (
                isinstance(argument, ast.Call)
                and isinstance(argument.func, ast.Attribute)
                and argument.func.attr == "Column"
                and argument.args
                and isinstance(argument.args[0], ast.Constant)
            ):
                columns.add(argument.args[0].value)
        result[table_name] = columns
    return result


def test_preview_migration_revision_and_model_parity() -> None:
    source = MIGRATION.read_text()
    assert 'revision: str = "0007_preview_persistence"' in source
    assert 'down_revision: Union[str, Sequence[str], None] = "0006_event_provenance"' in source
    migration_columns = _migration_columns()
    for table_name in ("preview_publications", "preview_access_receipts"):
        assert migration_columns[table_name] == _model_columns(table_name)


def test_preview_migration_has_cross_dialect_no_resurrection_guards() -> None:
    source = MIGRATION.read_text()
    assert "uq_preview_version_identity" not in source
    for state in ("reserved", "ready", "retiring", "retired"):
        assert state in source
    assert "trg_preview_publication_update_guard" in source
    assert "trg_preview_publication_delete_guard" in source
    assert "pilot_guard_preview_publication_mutation" in source
    assert "preview publication material is immutable" in source
    assert "preview publication cannot be resurrected" in source
    assert "trg_preview_access_update_guard" in source
    assert "pilot_guard_preview_access_mutation" in source


def test_preview_migration_uses_only_bounded_security_definer_surfaces() -> None:
    source = MIGRATION.read_text()
    functions = (
        "pilot_get_active_site_config_sha256",
        "pilot_get_preview_object_context",
        "pilot_prepare_preview_publication",
        "pilot_finalize_preview_receipt",
        "pilot_get_preview_receipt",
        "pilot_commit_preview_access",
        "pilot_claim_preview_receipts_for_retention",
        "pilot_finalize_preview_retirement",
        "pilot_preview_version_is_protected",
        "pilot_prune_preview_access_receipts",
        "pilot_retire_expired_preview_intents",
    )
    for function in functions:
        assert f"FUNCTION {function}" in source
    assert source.count("SECURITY DEFINER") >= len(functions)
    assert source.count("SET search_path = pg_catalog, public") >= len(functions)
    assert "p_limit BETWEEN 1 AND 1000" in source
    assert "SKIP LOCKED" in source
    assert "16777216" in source

    assert "REVOKE ALL ON TABLE preview_publications" in source
    assert "REVOKE ALL ON TABLE preview_access_receipts" in source
    for role in ("kuzet_runtime", "kuzet_api", "kuzet_retention"):
        assert role in source
    assert "GRANT INSERT" not in source
    assert "GRANT UPDATE" not in source
    assert "GRANT DELETE" not in source
    assert "GRANT ALL" not in source


def test_preview_security_definers_cannot_advance_retention_time() -> None:
    source = MIGRATION.read_text()

    assert "created_at > clock_timestamp() + interval '5 minutes'" in source
    assert source.count("effective_cutoff := LEAST(") == 2
    assert (
        "clock_timestamp() - make_interval(days => retention_days)"
        in source
    )
    assert (
        "clock_timestamp() - make_interval(days => metadata_retention_days)"
        in source
    )
    assert "effective_observed_at := LEAST(" in source
    assert "p_retired_at IS NULL" in source
    assert "retired_at = GREATEST(" in source
    assert "CASE WHEN p_observed_at IS NULL THEN true" in source
    assert "access_time := clock_timestamp()" in source
    assert "requested_time > clock_timestamp() + interval '5 minutes'" in source
    assert "requested_time < clock_timestamp() - interval '5 minutes'" in source


def test_preview_sql_requires_exact_readiness_and_redacted_atomic_audit() -> None:
    source = MIGRATION.read_text()
    assert "candidate.evidence_status = 'ready'" in source
    assert "evidence.status = 'ready'" in source
    assert "evidence.evidence_id = publication.evidence_id" in source
    assert "evidence.event_id = publication.event_id" in source
    assert "actor.is_active" in source
    assert "preview.accessed" in source
    assert "receipt_sha256" in source
    audit_section = source[source.index("CREATE FUNCTION pilot_commit_preview_access") :]
    audit_section = audit_section[: audit_section.index("CREATE FUNCTION", 40)]
    for forbidden in (
        "'object_key'",
        "'etag'",
        "'version_id'",
        "'kms_key_id'",
        "'source_reference'",
    ):
        assert forbidden not in audit_section
