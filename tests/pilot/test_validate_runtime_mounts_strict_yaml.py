"""Strict parser regressions for the production mount validator."""

from __future__ import annotations

import unittest
from pathlib import Path

from protector.pilot.trusted_yaml import StrictYAMLError
from scripts.pilot import validate_runtime_mounts


ROOT = Path(__file__).resolve().parents[2]


class ValidateRuntimeMountsStrictYAMLTests(unittest.TestCase):
    def test_reviewed_mapping_rejects_duplicates_anchors_and_aliases(
        self,
    ) -> None:
        cases = (
            (
                b"schema_version: first\nschema_version: second\n",
                "duplicate YAML mapping key",
            ),
            (
                b"base: &base\n  value: one\n",
                "anchors are not allowed",
            ),
            (
                b"copy: *missing\n",
                "aliases are not allowed",
            ),
        )
        for payload, expected in cases:
            with self.subTest(expected=expected):
                with self.assertRaisesRegex(StrictYAMLError, expected):
                    validate_runtime_mounts._parse_reviewed_mapping(payload)

    def test_validator_routes_all_reviewed_yaml_through_strict_loader(
        self,
    ) -> None:
        source = (
            ROOT / "scripts" / "pilot" / "validate_runtime_mounts.py"
        ).read_text(encoding="utf-8")

        self.assertNotIn("yaml.safe_load", source)
        self.assertGreaterEqual(source.count("_parse_reviewed_mapping("), 4)


if __name__ == "__main__":
    unittest.main()
