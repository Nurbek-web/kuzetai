"""Static contract checks for the pending NVIDIA target launch instructions.

These tests validate documented argv and network wiring only.  They do not run
Docker, DeepStream, CUDA, TensorRT, or the 20-camera acceptance workload.
"""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
TARGET_ACCEPTANCE = (
    REPOSITORY_ROOT / "deploy" / "pilot" / "TARGET_ACCEPTANCE.md"
)
MOUNT_VALIDATOR = (
    REPOSITORY_ROOT / "scripts" / "pilot" / "validate_runtime_mounts.py"
)
MOUNT_CONTRACT = (
    REPOSITORY_ROOT
    / "protector"
    / "pilot"
    / "runtime"
    / "mount_contract.py"
)
DEPLOYMENT_RUNBOOK = (
    REPOSITORY_ROOT / "docs" / "pilot" / "deployment_runbook.md"
)


class TargetAcceptanceLaunchContractTests(unittest.TestCase):
    def test_documented_launch_supplies_production_secrets_and_site_authority(
        self,
    ) -> None:
        document = TARGET_ACCEPTANCE.read_text(encoding="utf-8")

        expected_exports = (
            "export PILOT_SITE_ID=",
            "export PILOT_RUNTIME_DATABASE_URL_SECRET=",
            "export PILOT_RUNTIME_OBJECT_STORE_ACCESS_KEY_SECRET=",
            "export PILOT_RUNTIME_OBJECT_STORE_SECRET_KEY_SECRET=",
            "export PILOT_RUNTIME_JOURNAL_SOURCE=",
            "export PILOT_RUNTIME_PREVIEW_SOURCE=",
            "export PILOT_RUNTIME_OBJECT_STORE_REGION=",
        )
        expected_validator_arguments = (
            '--database-url-secret "$PILOT_RUNTIME_DATABASE_URL_SECRET"',
            (
                "--object-store-access-key-secret "
                '"$PILOT_RUNTIME_OBJECT_STORE_ACCESS_KEY_SECRET"'
            ),
            (
                "--object-store-secret-key-secret "
                '"$PILOT_RUNTIME_OBJECT_STORE_SECRET_KEY_SECRET"'
            ),
            '--runtime-journal-source "$PILOT_RUNTIME_JOURNAL_SOURCE"',
            '--runtime-preview-source "$PILOT_RUNTIME_PREVIEW_SOURCE"',
        )
        expected_runtime_arguments = (
            '--site-id "$PILOT_SITE_ID"',
            "--database-url-secret /run/secrets/runtime_database_url",
            (
                "--object-store-access-key-secret "
                "/run/secrets/runtime_object_store_access_key"
            ),
            (
                "--object-store-secret-key-secret "
                "/run/secrets/runtime_object_store_secret_key"
            ),
            '--object-store-region "$PILOT_RUNTIME_OBJECT_STORE_REGION"',
        )

        for expected in (
            *expected_exports,
            *expected_validator_arguments,
            *expected_runtime_arguments,
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, document)
        self.assertIn(
            ')\ntest "${#PILOT_RUNTIME_MOUNT_ARGV[@]}" -eq 70',
            document,
        )

    def test_documented_launch_connects_all_precreated_runtime_networks_before_start(
        self,
    ) -> None:
        document = TARGET_ACCEPTANCE.read_text(encoding="utf-8")

        self.assertIn("export PILOT_DATA_NETWORK=", document)
        self.assertIn("export PILOT_STORAGE_EGRESS_NETWORK=", document)
        camera_connect = document.index(
            'docker network connect "$PILOT_CAMERA_LAN_NETWORK" "$runtime_id"'
        )
        data_connect = document.index(
            'docker network connect "$PILOT_DATA_NETWORK" "$runtime_id"'
        )
        storage_connect = document.index(
            'docker network connect "$PILOT_STORAGE_EGRESS_NETWORK" "$runtime_id"'
        )
        start = document.index('docker start --attach "$runtime_id"')

        self.assertLess(camera_connect, start)
        self.assertLess(data_connect, start)
        self.assertLess(storage_connect, start)

    def test_validator_and_mount_contract_require_exact_bounded_secret_sources(
        self,
    ) -> None:
        validator = MOUNT_VALIDATOR.read_text(encoding="utf-8")
        contract = MOUNT_CONTRACT.read_text(encoding="utf-8")

        for option in (
            '"--database-url-secret"',
            '"--object-store-access-key-secret"',
            '"--object-store-secret-key-secret"',
            '"--runtime-journal-source"',
            '"--runtime-preview-source"',
        ):
            with self.subTest(option=option):
                self.assertIn(
                    f"parser.add_argument({option}, type=Path, required=True)",
                    validator,
                )
        for target in (
            'Path("/run/secrets/runtime_database_url")',
            'Path("/run/secrets/runtime_object_store_access_key")',
            'Path("/run/secrets/runtime_object_store_secret_key")',
            'Path("/var/lib/kuzet/journal")',
            'Path("/var/lib/kuzet/previews")',
        ):
            with self.subTest(target=target):
                self.assertIn(target, contract)
        self.assertIn("storage_encryption_attested", contract)
        self.assertIn("storage_quota_bytes", contract)

    def test_raw_launch_matches_read_only_runtime_hardening_contract(self) -> None:
        document = TARGET_ACCEPTANCE.read_text(encoding="utf-8")

        for expected in (
            "set -euo pipefail",
            "export PILOT_RUNTIME_MEMORY_LIMIT=",
            "export PILOT_RUNTIME_CPU_LIMIT=",
            "export PILOT_RUNTIME_SHM_LIMIT=",
            "--user 10001:10001",
            "--ipc private",
            "--init",
            '--stop-timeout "$PILOT_RUNTIME_STOP_TIMEOUT_SECONDS"',
            '--memory "$PILOT_RUNTIME_MEMORY_LIMIT"',
            '--cpus "$PILOT_RUNTIME_CPU_LIMIT"',
            '--shm-size "$PILOT_RUNTIME_SHM_LIMIT"',
            "--tmpfs /tmp:rw,noexec,nosuid,nodev,size=134217728,mode=1777",
            "--tmpfs /var/tmp:rw,noexec,nosuid,nodev,size=16777216,mode=1777",
            "--log-driver json-file",
            "--log-opt max-size=10m",
            "--log-opt max-file=3",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, document)
        self.assertNotIn("--memory 16g", document)
        self.assertNotIn("--cpus 8", document)
        self.assertLess(
            document.index("set -euo pipefail"),
            document.index("docker create"),
        )
        launch_section = document[document.index("Create the runtime stopped") :]
        self.assertIn("```bash\nset -euo pipefail\n", launch_section)

    def test_runtime_code_digest_is_exported_before_image_build(self) -> None:
        document = TARGET_ACCEPTANCE.read_text(encoding="utf-8")
        export = "export PILOT_RUNTIME_CODE_SHA256=REPLACE_WITH_64_HEX"

        self.assertEqual(document.count(export), 1)
        self.assertLess(document.index(export), document.index("docker build"))

    def test_gpu_shell_expression_preserves_required_inner_capability_quotes(
        self,
    ) -> None:
        document = TARGET_ACCEPTANCE.read_text(encoding="utf-8")
        gpu_line = next(
            line.strip()
            for line in document.splitlines()
            if line.strip().startswith("--gpus ")
        )
        shell_expression = gpu_line.removeprefix("--gpus ").removesuffix(" \\")
        result = subprocess.run(
            [
                "bash",
                "-c",
                (
                    "PILOT_GPU_UUID=GPU-fixture\n"
                    f"set -- {shell_expression}\n"
                    "printf '%s\\n' \"$#\" \"$1\"\n"
                ),
            ],
            check=True,
            capture_output=True,
            text=True,
        )

        self.assertEqual(
            result.stdout.splitlines(),
            [
                "1",
                'device=GPU-fixture,"capabilities=compute,utility,video"',
            ],
        )

    def test_runbook_keeps_compose_runtime_render_only_until_wrapper_attestation(
        self,
    ) -> None:
        runbook = DEPLOYMENT_RUNBOOK.read_text(encoding="utf-8")
        start_section = runbook[runbook.index("## Start the shared runtime") :]
        normalized = " ".join(start_section.split())

        for required in (
            "sole authoritative pending runtime launch",
            "Compose runtime template is render-only",
            "Compose runtime activation is **BLOCKED**",
            (
                "The raw mount validator does not validate the rendered "
                "Compose secret and directory layout"
            ),
            (
                "a reviewed host wrapper attests the rendered container's "
                "exact image ID and config"
            ),
            "Manual inspection does not close this gate",
        ):
            with self.subTest(required=required):
                self.assertIn(required, normalized)
        self.assertNotIn("up -d runtime", start_section)


if __name__ == "__main__":
    unittest.main()
