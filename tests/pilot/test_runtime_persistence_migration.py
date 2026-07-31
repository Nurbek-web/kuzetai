from __future__ import annotations

from pathlib import Path

from scripts.pilot.bootstrap_roles import _grant_runtime_access

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "migrations/versions/0008_runtime_persistence.py"
PRODUCTION_REPOSITORY = (
    ROOT / "protector/pilot/runtime/production_repository.py"
)
ROLE_BOOTSTRAP = ROOT / "scripts/pilot/bootstrap_roles.py"

RUNTIME_FUNCTIONS = {
    "pilot_get_runtime_claim_state": "text",
    "pilot_claim_runtime_writer": "text, text",
    "pilot_get_runtime_configuration": "text, text",
    "pilot_get_runtime_event": "text, text, uuid",
    "pilot_activate_runtime_camera_epoch": (
        "text, text, text, uuid, uuid, timestamptz"
    ),
    "pilot_set_runtime_candidate_evidence_status": (
        "text, text, uuid, text"
    ),
    "pilot_finalize_runtime_evidence": "text, text, jsonb",
}


def test_runtime_persistence_revision_and_bounded_surfaces() -> None:
    source = MIGRATION.read_text(encoding="utf-8")

    assert 'revision: str = "0008_runtime_persistence"' in source
    assert (
        'down_revision: Union[str, Sequence[str], None] = '
        '"0007_preview_persistence"'
    ) in source
    for function in RUNTIME_FUNCTIONS:
        assert f"FUNCTION {function}" in source
    assert source.count("SECURITY DEFINER") >= len(RUNTIME_FUNCTIONS)
    assert source.count("SET search_path = pg_catalog, public") >= len(
        RUNTIME_FUNCTIONS
    )
    assert source.count("FROM PUBLIC") >= len(RUNTIME_FUNCTIONS)


def test_runtime_functions_revalidate_exact_current_authority() -> None:
    source = MIGRATION.read_text(encoding="utf-8")

    for authority_column in (
        "runtime_session_id",
        "writer_generation",
        "configuration_activation_generation",
        "receipt_sha256",
        "ruleset_revision_id",
        "ruleset_sha256",
        "config_revision_id",
        "config_sha256",
        "source_epoch",
    ):
        assert authority_column in source
    assert "sha256(convert_to(receipt_canonical_json, 'UTF8'))" in source
    assert "FOR UPDATE OF active, writer" in source
    assert "runtime_writer_sessions" in source
    assert "camera_epoch_history" in source
    assert "candidate_event_provenance" in source
    assert "jsonb_object_length" not in source
    assert "jsonb_object_keys" in source
    assert (
        "provenance.rule_revision_sha256 =\n"
        "                   receipt->'rule_revision_digests'"
    ) in source


def test_runtime_epoch_locks_writer_before_receipt_share_validation() -> None:
    source = MIGRATION.read_text(encoding="utf-8")
    epoch = source[
        source.index("CREATE FUNCTION pilot_activate_runtime_camera_epoch") :
        source.index(
            "CREATE FUNCTION pilot_set_runtime_candidate_evidence_status"
        )
    ]

    assert epoch.index("FOR UPDATE OF active, writer") < epoch.index(
        "pilot_runtime_receipt_is_current"
    )


def test_writer_and_epoch_times_cannot_poison_future_runtime_claims() -> None:
    source = MIGRATION.read_text(encoding="utf-8")
    claim = source[
        source.index("CREATE FUNCTION pilot_claim_runtime_writer") :
        source.index("CREATE FUNCTION pilot_get_runtime_configuration")
    ]
    epoch = source[
        source.index("CREATE FUNCTION pilot_activate_runtime_camera_epoch") :
        source.index(
            "CREATE FUNCTION pilot_set_runtime_candidate_evidence_status"
        )
    ]

    assert (
        "requested_issued_at NOT BETWEEN\n"
        "                 CURRENT_TIMESTAMP - interval '5 minutes'\n"
        "                 AND CURRENT_TIMESTAMP + interval '5 minutes'"
    ) in claim
    assert (
        "p_activated_at NOT BETWEEN\n"
        "                 CURRENT_TIMESTAMP - interval '5 minutes'\n"
        "                 AND CURRENT_TIMESTAMP + interval '5 minutes'"
    ) in epoch


def test_terminal_evidence_is_exactly_event_scoped_and_bounded() -> None:
    source = MIGRATION.read_text(encoding="utf-8")
    finalize = source[
        source.index("CREATE FUNCTION pilot_finalize_runtime_evidence") :
        source.index("def _apply_postgresql_runtime_grants")
    ]

    assert "jsonb_typeof(p_evidence->'object_key') <> 'string'" in finalize
    assert (
        "(p_evidence->>'object_key') <>\n"
        "                    (\n"
        "                      'events/' || (p_evidence->>'event_id')"
    ) in finalize
    assert (
        "(p_evidence->>'source_reference') <>\n"
        "                    (\n"
        "                      'nvr://' || (receipt->>'site_id') || '/'"
    ) in finalize
    assert "requested_start > candidate.opened_at" in finalize
    assert "requested_end < candidate.last_seen_at" in finalize


def test_runtime_role_has_functions_not_table_privileges() -> None:
    source = MIGRATION.read_text(encoding="utf-8")

    assert "REVOKE ALL ON TABLE" in source
    assert "REVOKE CREATE ON SCHEMA public FROM kuzet_runtime" in source
    assert "FROM kuzet_runtime" in source
    assert "GRANT EXECUTE ON FUNCTION" in source
    assert "pilot_ingest_candidate(jsonb, jsonb)" in source
    assert "pilot_get_active_site_config_sha256(text)" in source
    assert "TO kuzet_retention" in source
    for unsafe_role_attribute in (
        "role.rolsuper",
        "role.rolcreatedb",
        "role.rolcreaterole",
        "role.rolinherit",
        "role.rolreplication",
        "role.rolbypassrls",
        "pg_auth_members",
    ):
        assert unsafe_role_attribute in source
    owner_guard = source[
        source.index("SELECT role.rolsuper") :
        source.index("INTO runtime_is_unsafe")
    ]
    for protected_table in (
        "sites",
        "cameras",
        "model_artifacts",
        "site_config_revisions",
        "camera_ruleset_revisions",
        "camera_rule_revisions",
        "configuration_activations",
        "active_pilot_configurations",
        "runtime_writer_authorities",
        "runtime_writer_sessions",
        "camera_epoch_authorities",
        "camera_epoch_history",
        "legacy_candidate_imports",
        "candidate_events",
        "candidate_event_provenance",
        "evidence",
        "preview_publications",
        "preview_access_receipts",
    ):
        assert f"'public.{protected_table}'::regclass" in owner_guard
    upgrade = source[: source.index("def downgrade()")]
    for privilege in (
        "GRANT SELECT ON TABLE",
        "GRANT INSERT ON TABLE",
        "GRANT UPDATE ON TABLE",
        "GRANT DELETE ON TABLE",
        "GRANT ALL",
    ):
        assert privilege not in upgrade


def test_every_runtime_security_definer_surface_is_explicitly_bounded() -> None:
    source = MIGRATION.read_text(encoding="utf-8")
    grants = source[
        source.index("def _apply_postgresql_runtime_grants") :
        source.index("def downgrade()")
    ]
    compact_grants = (
        " ".join(grants.split())
        .replace("( ", "(")
        .replace(" )", ")")
    )

    public_revokes = (
        "pilot_get_active_site_config_sha256(text)",
        "pilot_guard_storage_reconfiguration()",
        "pilot_runtime_receipt_is_current(text, text)",
        *(
            f"{function}({signature})"
            for function, signature in RUNTIME_FUNCTIONS.items()
        ),
    )
    for surface in public_revokes:
        assert surface in compact_grants
        surface_start = compact_grants.index(surface)
        assert "FROM PUBLIC" in compact_grants[
            surface_start : surface_start + len(surface) + 50
        ]

    runtime_grant_start = compact_grants.index(
        "GRANT EXECUTE ON FUNCTION pilot_get_runtime_claim_state"
    )
    runtime_grants = compact_grants[
        runtime_grant_start :
        compact_grants.index("TO kuzet_runtime;", runtime_grant_start)
    ]
    for function, signature in RUNTIME_FUNCTIONS.items():
        assert f"{function}({signature})" in runtime_grants
    for inherited_surface in (
        "pilot_ingest_candidate(jsonb, jsonb)",
        "pilot_get_active_site_config_sha256(text)",
        "pilot_get_preview_object_context(text, uuid, uuid, uuid)",
        "pilot_prepare_preview_publication(jsonb)",
        "pilot_finalize_preview_receipt(jsonb, jsonb)",
    ):
        assert inherited_surface in runtime_grants
    assert "pilot_runtime_receipt_is_current" not in runtime_grants
    assert "pilot_guard_storage_reconfiguration" not in runtime_grants


def test_production_repository_calls_only_the_granted_runtime_surface() -> None:
    migration = MIGRATION.read_text(encoding="utf-8")
    runtime = PRODUCTION_REPOSITORY.read_text(encoding="utf-8")
    bootstrap = ROLE_BOOTSTRAP.read_text(encoding="utf-8")

    for function in RUNTIME_FUNCTIONS:
        assert f"public.{function}(" in runtime
        assert f"{function}(" in migration
    assert "public.pilot_ingest_candidate(" in runtime
    assert "REVOKE ALL ON TABLE" in migration
    assert "FROM kuzet_runtime" in migration
    assert "NOT role.rolsuper" in bootstrap
    assert "NOT role.rolbypassrls" in bootstrap
    assert "NOT role.rolinherit" in bootstrap
    assert "FROM kuzet_api, kuzet_runtime, kuzet_retention" in bootstrap


class _RoleGrantResult:
    def __init__(self, row: tuple[object, ...]) -> None:
        self._row = row

    def fetchone(self) -> tuple[object, ...]:
        return self._row


class _RoleGrantConnection:
    def __init__(self) -> None:
        self.statements: list[str] = []

    def execute(self, statement: object) -> _RoleGrantResult:
        rendered = str(statement)
        self.statements.append(rendered)
        if "SELECT count(*) = 3" in rendered:
            return _RoleGrantResult((True,))
        if rendered == "SELECT current_database()":
            return _RoleGrantResult(("kuzet_pilot",))
        return _RoleGrantResult((None,))


def test_role_grant_rerun_erases_seeded_service_acl_drift_before_regrant() -> None:
    connection = _RoleGrantConnection()
    seeded_acl = {
        role: {
            "tables": {"stale_table_privilege"},
            "sequences": {"stale_sequence_privilege"},
            "routines": {"stale_routine_privilege"},
        }
        for role in ("kuzet_api", "kuzet_runtime", "kuzet_retention")
    }

    _grant_runtime_access(connection)  # type: ignore[arg-type]

    compact = [
        " ".join(statement.split())
        .replace("( ", "(")
        .replace(" )", ")")
        for statement in connection.statements
    ]
    reset_indexes: list[int] = []
    for acl_kind, sql_kind in (
        ("tables", "TABLES"),
        ("sequences", "SEQUENCES"),
        ("routines", "ROUTINES"),
    ):
        reset = (
            f"REVOKE ALL PRIVILEGES ON ALL {sql_kind} IN SCHEMA public "
            "FROM kuzet_api, kuzet_runtime, kuzet_retention"
        )
        index = compact.index(reset)
        reset_indexes.append(index)
        for role_acl in seeded_acl.values():
            role_acl[acl_kind].clear()
    assert all(not privileges for acl in seeded_acl.values() for privileges in acl.values())
    first_exact_grant = next(
        index
        for index, statement in enumerate(compact)
        if statement.startswith("GRANT SELECT ON TABLE")
    )
    assert max(reset_indexes) < first_exact_grant
    for routine in (
        "pilot_get_preview_receipt(text, uuid)",
        "pilot_claim_runtime_writer(text, text)",
        "pilot_prune_archived_audit(text)",
        "pilot_retire_expired_preview_intents(text, timestamptz, integer)",
    ):
        assert any(routine in statement for statement in compact)


def test_storage_is_immutable_after_first_activation_in_database() -> None:
    source = MIGRATION.read_text(encoding="utf-8")

    assert "pilot_guard_storage_reconfiguration" in source
    assert "trg_configuration_activation_storage_guard" in source
    assert "BEFORE INSERT ON configuration_activations" in source
    assert "canonical_config->'storage'" in source
    assert "proposed_storage IS DISTINCT FROM current_storage" in source
    assert "reviewed storage is immutable after first activation" in source
    assert "pg_try_advisory_xact_lock" in source
    assert "'kuzet-retention:' || NEW.site_id" in source
    assert "hashtextextended(" in source
    assert "12" in source
    assert "SET search_path = pg_catalog, public" in source
    guard = source[
        source.index("CREATE FUNCTION pilot_guard_storage_reconfiguration") :
        source.index(
            "CREATE TRIGGER\n"
            "          trg_configuration_activation_storage_guard"
        )
    ]
    assert guard.index("pg_try_advisory_xact_lock") < guard.index(
        "FROM public.active_pilot_configurations"
    )
    assert guard.index("IF NOT FOUND") < guard.index(
        "proposed_storage IS DISTINCT FROM current_storage"
    )
    downgrade = source[source.index("def downgrade()") :]
    assert (
        "DROP TRIGGER IF EXISTS\n"
        "          trg_configuration_activation_storage_guard"
        in downgrade
    )
    assert "pilot_guard_storage_reconfiguration()" in downgrade


def test_downgrade_revokes_and_drops_runtime_functions() -> None:
    source = MIGRATION.read_text(encoding="utf-8")
    downgrade = source[source.index("def downgrade()") :]
    compact = (
        " ".join(downgrade.split())
        .replace("( ", "(")
        .replace(" )", ")")
    )

    for function, signature in RUNTIME_FUNCTIONS.items():
        assert f"DROP FUNCTION IF EXISTS {function}" in downgrade
        assert f"{function}({signature})" in compact
    assert "FROM kuzet_runtime" in compact
    retention_revoke_start = compact.index(
        "REVOKE EXECUTE ON FUNCTION "
        "pilot_get_active_site_config_sha256(text)"
    )
    retention_revoke_end = compact.index(
        "FROM kuzet_retention;",
        retention_revoke_start,
    )
    retention_revoke = compact[
        retention_revoke_start:retention_revoke_end
    ]
    active_config_signature = (
        "pilot_get_active_site_config_sha256(text)"
    )
    operational_prune_signature = (
        "pilot_prune_operational_metadata("
        "text, timestamptz, integer)"
    )
    assert active_config_signature in retention_revoke
    assert operational_prune_signature in retention_revoke
    assert retention_revoke.index(
        active_config_signature
    ) < retention_revoke.index(operational_prune_signature)
    assert (
        "DROP FUNCTION IF EXISTS "
        "pilot_runtime_receipt_is_current(text, text)"
    ) in compact
