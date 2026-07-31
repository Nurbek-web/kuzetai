from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MIGRATION_CARDINALITY_GUARDS = {
    "migrations/versions/0006_event_provenance.py": {
        "(SELECT count(*) FROM jsonb_object_keys(candidate)) <> 14": 1,
        "(SELECT count(*) FROM jsonb_object_keys(provenance)) <> 16": 1,
    },
    "migrations/versions/0008_runtime_persistence.py": {
        "(SELECT count(*) FROM jsonb_object_keys(receipt)) <> 11": 2,
        (
            "(SELECT count(*) FROM "
            "jsonb_object_keys(receipt->'rule_revision_digests')) "
            "NOT BETWEEN 1 AND 512"
        ): 1,
        "(SELECT count(*) FROM jsonb_object_keys(p_evidence)) <> 10": 1,
    },
}


class PostgreSQLJsonbCompatibilityTests(unittest.TestCase):
    def test_object_cardinality_uses_stock_postgresql_primitives(self) -> None:
        for relative_path, expected_guards in (
            MIGRATION_CARDINALITY_GUARDS.items()
        ):
            with self.subTest(migration=relative_path):
                source = (ROOT / relative_path).read_text(encoding="utf-8")
                compact = (
                    " ".join(source.split())
                    .replace("( ", "(")
                    .replace(" )", ")")
                )

                self.assertNotIn("jsonb_object_length(", source)
                for guard, expected_count in expected_guards.items():
                    self.assertEqual(
                        compact.count(guard),
                        expected_count,
                        guard,
                    )


if __name__ == "__main__":
    unittest.main()
