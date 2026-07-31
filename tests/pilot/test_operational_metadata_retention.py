from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from protector.pilot.operational_retention import (
    OperationalMetadataPruneCounts,
    OperationalMetadataRetentionCoordinator,
)

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)


class _Repository:
    def __init__(
        self,
        *,
        result: OperationalMetadataPruneCounts | None = None,
        failure: BaseException | None = None,
    ) -> None:
        self.result = result or OperationalMetadataPruneCounts(
            health_samples=0,
            observations=0,
        )
        self.failure = failure
        self.calls: list[tuple[str, datetime, int]] = []

    def prune_operational_metadata(
        self,
        *,
        site_id: str,
        cutoff_at: datetime,
        limit: int,
    ) -> OperationalMetadataPruneCounts:
        self.calls.append((site_id, cutoff_at, limit))
        if self.failure is not None:
            raise self.failure
        return self.result


class OperationalMetadataRetentionTests(unittest.TestCase):
    def test_coordinator_prunes_both_live_append_surfaces_with_one_finite_bound(
        self,
    ) -> None:
        repository = _Repository(
            result=OperationalMetadataPruneCounts(
                health_samples=17,
                observations=4,
            )
        )
        coordinator = OperationalMetadataRetentionCoordinator(
            repository=repository,
            site_id="site-1",
            metadata_retention_days=30,
            batch_size=100,
            clock=lambda: NOW,
        )

        result = coordinator.run_once()

        self.assertEqual(
            repository.calls,
            [("site-1", NOW - timedelta(days=30), 100)],
        )
        self.assertEqual(result.health_samples_pruned, 17)
        self.assertEqual(result.observations_pruned, 4)
        self.assertEqual(result.failed, 0)
        self.assertEqual(result.failure_reasons, ())

    def test_repository_failure_is_a_fail_closed_retention_result(self) -> None:
        coordinator = OperationalMetadataRetentionCoordinator(
            repository=_Repository(failure=RuntimeError("database unavailable")),
            site_id="site-1",
            metadata_retention_days=30,
            batch_size=100,
            clock=lambda: NOW,
        )

        result = coordinator.run_once()

        self.assertEqual(result.health_samples_pruned, 0)
        self.assertEqual(result.observations_pruned, 0)
        self.assertEqual(result.failed, 1)
        self.assertEqual(
            result.failure_reasons,
            ("operational_metadata_prune_failed",),
        )

    def test_repository_cannot_report_more_than_either_table_batch(self) -> None:
        coordinator = OperationalMetadataRetentionCoordinator(
            repository=_Repository(
                result=OperationalMetadataPruneCounts(
                    health_samples=101,
                    observations=0,
                )
            ),
            site_id="site-1",
            metadata_retention_days=30,
            batch_size=100,
            clock=lambda: NOW,
        )

        result = coordinator.run_once()

        self.assertEqual(result.failed, 1)
        self.assertEqual(result.health_samples_pruned, 0)
        self.assertEqual(result.observations_pruned, 0)

    def test_migration_owns_site_scoped_policy_bound_pruning_function(self) -> None:
        migration = (
            ROOT / "migrations/versions/0008_runtime_persistence.py"
        ).read_text(encoding="utf-8")
        function = migration[
            migration.index(
                "CREATE FUNCTION pilot_prune_operational_metadata"
            ) : migration.index(
                "def _apply_postgresql_runtime_grants"
            )
        ]

        self.assertIn(
            "{storage,retention,metadata_retention_days}",
            function,
        )
        self.assertIn("LEAST(", function)
        self.assertIn("clock_timestamp() - make_interval", function)
        self.assertIn("public.camera_health_samples", function)
        self.assertIn("public.observations", function)
        self.assertGreaterEqual(function.count("camera.site_id = p_site_id"), 2)
        self.assertGreaterEqual(function.count("LIMIT p_limit"), 2)
        self.assertGreaterEqual(function.count("FOR UPDATE"), 2)
        self.assertEqual(function.count("LANGUAGE plpgsql"), 1)
        self.assertEqual(
            function.count("WHERE active.site_id = p_site_id"),
            1,
        )
        self.assertIn("'health_samples'", function)
        self.assertIn("'observations'", function)

        compact = (
            " ".join(migration.split())
            .replace("( ", "(")
            .replace(" )", ")")
        )
        signature = (
            "pilot_prune_operational_metadata("
            "text, timestamptz, integer)"
        )
        self.assertIn(f"{signature} FROM PUBLIC", compact)
        self.assertIn(f"{signature} TO kuzet_retention", compact)
        self.assertIn(f"DROP FUNCTION IF EXISTS {signature}", compact)

    def test_database_intrinsically_upserts_only_latest_health_per_camera(
        self,
    ) -> None:
        migration = (
            ROOT / "migrations/versions/0008_runtime_persistence.py"
        ).read_text(encoding="utf-8")

        self.assertIn(
            "CREATE UNIQUE INDEX uq_camera_health_latest_per_camera",
            migration,
        )
        self.assertIn(
            "CREATE FUNCTION pilot_upsert_camera_health_sample(",
            migration,
        )
        upsert = migration[
            migration.index(
                "CREATE FUNCTION pilot_upsert_camera_health_sample("
            ) : migration.index(
                "CREATE FUNCTION pilot_prune_operational_metadata("
            )
        ]
        self.assertIn("SECURITY DEFINER", upsert)
        self.assertIn("ON CONFLICT (camera_id)", upsert)
        self.assertIn("DO UPDATE SET", upsert)
        self.assertNotIn("jsonb_object_length", upsert)
        self.assertIn("jsonb_object_keys", upsert)
        self.assertIn("camera.site_id = p_site_id", upsert)
        self.assertIn("camera.enabled", upsert)
        self.assertIn("jsonb_array_length(", upsert)
        self.assertIn(") = 20", upsert)
        self.assertIn("jsonb_array_elements(", upsert)
        self.assertIn("feed->>'camera_id' = camera.camera_id", upsert)
        self.assertIn("ROW_NUMBER() OVER (", migration)
        self.assertIn("PARTITION BY camera_id", migration)
        self.assertIn(
            "pilot_upsert_camera_health_sample(text, jsonb) FROM PUBLIC",
            " ".join(migration.split()),
        )
        self.assertIn(
            "DROP INDEX IF EXISTS uq_camera_health_latest_per_camera",
            migration[migration.index("def downgrade()") :],
        )
        models = (
            ROOT / "protector/pilot/storage/models.py"
        ).read_text(encoding="utf-8")
        self.assertIn(
            '"uq_camera_health_latest_per_camera",',
            models,
        )
        self.assertIn(').ddl_if(dialect="postgresql")', models)
        downgrade = migration[migration.index("def downgrade()") :]
        self.assertIn(
            "GRANT INSERT ON TABLE\n"
            "              public.camera_health_samples,\n"
            "              public.observations",
            downgrade,
        )

    def test_retention_role_gets_function_not_metadata_table_dml(self) -> None:
        bootstrap = (
            ROOT / "scripts/pilot/bootstrap_roles.py"
        ).read_text(encoding="utf-8")
        retention_tables = bootstrap[
            bootstrap.index(
                "GRANT SELECT ON TABLE\n"
                "          sites, cameras, candidate_events"
            ) : bootstrap.index(
                "GRANT EXECUTE ON FUNCTION\n"
                "          public.pilot_get_active_site_config_sha256"
            )
        ]

        self.assertNotIn("camera_health_samples", retention_tables)
        self.assertNotIn("observations", retention_tables)
        api_inserts = bootstrap[
            bootstrap.index(
                "GRANT INSERT ON TABLE"
            ) : bootstrap.index(
                "GRANT UPDATE ON TABLE"
            )
        ]
        self.assertNotIn("camera_health_samples", api_inserts)
        self.assertNotIn("observations", api_inserts)
        api_functions = bootstrap[
            bootstrap.index(
                "GRANT EXECUTE ON FUNCTION\n"
                "          public.pilot_get_active_site_config_sha256"
            ) : bootstrap.index(
                "GRANT EXECUTE ON FUNCTION\n"
                "          public.pilot_get_runtime_claim_state"
            )
        ]
        self.assertIn(
            "public.pilot_upsert_camera_health_sample(text, jsonb)",
            api_functions,
        )
        self.assertIn(
            "public.pilot_prune_operational_metadata(\n"
            "            text, timestamptz, integer\n"
            "          )",
            bootstrap,
        )

    def test_production_loop_treats_metadata_prune_failure_as_fatal(self) -> None:
        service = (
            ROOT / "protector/pilot/retention_service.py"
        ).read_text(encoding="utf-8")

        self.assertIn(
            "OperationalMetadataRetentionCoordinator(",
            service,
        )
        self.assertIn("metadata_result = metadata.run_once()", service)
        self.assertIn("metadata_result.failed", service)

    def test_legacy_observation_append_is_closed_in_production(self) -> None:
        routes = (
            ROOT / "protector/pilot/api/routes_internal.py"
        ).read_text(encoding="utf-8")
        endpoint = routes[
            routes.index("def ingest_observation(") :
            routes.index("class HealthSampleRequest")
        ]

        self.assertIn("context.telemetry is not None", endpoint)
        self.assertIn("legacy_observation_ingest_disabled", endpoint)
        self.assertLess(
            endpoint.index("context.telemetry is not None"),
            endpoint.index("context.repository.add_observation"),
        )

        persistence = routes[
            routes.index("def _persist_health_samples_in_session(") :
            routes.index("ModuleName = Literal[")
        ]
        self.assertIn('dialect.name == "postgresql"', persistence)
        self.assertIn(
            "public.pilot_upsert_camera_health_sample(",
            persistence,
        )

    def test_repository_validates_counts_before_committing_deletions(self) -> None:
        repository = (
            ROOT / "protector/pilot/storage/repositories.py"
        ).read_text(encoding="utf-8")
        method = repository[
            repository.index("def prune_operational_metadata(") :
            repository.index("def authorize_telemetry_epoch(")
        ]
        postgres = method[
            method.index('dialect.name == "postgresql"') :
            method.index(
                'exec_driver_sql("BEGIN IMMEDIATE")'
            )
        ]

        self.assertLess(
            postgres.index(
                "operational metadata prune returned invalid counts"
            ),
            postgres.index("session.commit()"),
        )


if __name__ == "__main__":
    unittest.main()
