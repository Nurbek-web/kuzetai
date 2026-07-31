from __future__ import annotations

import ast
import importlib.util
import unittest
from pathlib import Path

import protector.pilot.runtime.deepstream as deepstream
from protector.pilot.trusted_yaml import StrictYAMLError


_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_ADVERSARIAL_YAML = {
    "duplicate keys": b"schema_version: first\nschema_version: second\n",
    "anchor and alias": b"base: &base\n  key: value\ncopy: *base\n",
    "merge key": b"document:\n  <<:\n    key: value\n",
}


class AuthorityYamlStrictnessTests(unittest.TestCase):
    def _assert_strict_refusal(self, loader: object) -> None:
        self.assertTrue(callable(loader))
        for label, payload in _ADVERSARIAL_YAML.items():
            with self.subTest(label=label):
                with self.assertRaises(ValueError) as raised:
                    loader(payload)
                self.assertIsInstance(raised.exception.__cause__, StrictYAMLError)

    def test_replay_mount_contract_parser_rejects_ambiguous_yaml(self) -> None:
        if importlib.util.find_spec("sqlalchemy") is None:
            self.skipTest("project SQLAlchemy dependency is unavailable")
        import scripts.pilot.replay_20 as replay

        self._assert_strict_refusal(replay._load_runtime_mount_contract)

    def test_target_child_parser_rejects_ambiguous_yaml(self) -> None:
        self._assert_strict_refusal(
            lambda payload: deepstream._load_target_reviewed_mapping(
                payload,
                max_bytes=1024,
                label="target authority input",
            )
        )

    def test_provisioning_parser_rejects_ambiguous_yaml(self) -> None:
        if importlib.util.find_spec("sqlalchemy") is None:
            self.skipTest("project SQLAlchemy dependency is unavailable")
        import protector.pilot.provisioning as provisioning

        self._assert_strict_refusal(
            lambda payload: provisioning._load_reviewed_mapping(
                payload,
                max_bytes=1024,
                label="provisioning authority input",
            )
        )

    def test_authority_loaders_do_not_call_yaml_safe_load(self) -> None:
        authority_loaders = {
            "protector/pilot/acceptance.py": {"load_acceptance_manifest"},
            "protector/pilot/model_registry.py": {"load_model_entry"},
            "protector/pilot/provisioning.py": {"load_reviewed_inputs"},
            "protector/pilot/runtime/deepstream.py": {
                "configure_nvtracker",
                "main",
            },
            "scripts/pilot/build_engine.py": {"_load_build_spec"},
            "scripts/pilot/replay_20.py": {
                "_launch_staged_container",
                "_stage_reviewed_runtime_mounts",
            },
        }
        for relative_path, function_names in authority_loaders.items():
            source = (_REPOSITORY_ROOT / relative_path).read_text(encoding="utf-8")
            tree = ast.parse(source, filename=relative_path)
            functions = {
                node.name: ast.get_source_segment(source, node)
                for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name in function_names
            }
            self.assertEqual(set(functions), function_names)
            for function_name, function_source in functions.items():
                with self.subTest(path=relative_path, function=function_name):
                    self.assertIsNotNone(function_source)
                    self.assertNotIn("yaml.safe_load", function_source)


if __name__ == "__main__":
    unittest.main()
