import ast
import re
import subprocess
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


def _continued_commands(content: str, needle: str) -> tuple[str, ...]:
    lines = content.splitlines()
    commands: list[str] = []
    for index, line in enumerate(lines):
        if needle not in line:
            continue
        start = index
        while start > 0 and lines[start - 1].rstrip().endswith("\\"):
            start -= 1
        end = index
        while end < len(lines) - 1 and lines[end].rstrip().endswith("\\"):
            end += 1
        commands.append("\n".join(lines[start : end + 1]))
    return tuple(commands)


def test_retention_starts_only_after_destructive_authority_probes() -> None:
    deployment = (DOCS / "deployment_runbook.md").read_text()

    core_start = deployment.index("up -d api tls-proxy prometheus")
    probe_verdict = deployment.index("storage-probe-authority.verified")
    retention_start = deployment.index("up -d retention")

    assert core_start < probe_verdict < retention_start
    assert "up -d \\\n  api retention tls-proxy prometheus" not in deployment


def test_storage_probe_commands_are_provider_bound_and_finite() -> None:
    deployment = (DOCS / "deployment_runbook.md").read_text()

    for phrase in (
        "PILOT_S3_ENDPOINT",
        "PILOT_S3_REGION",
        "PILOT_STORAGE_PROBE_BINDING_SHA256",
        "PILOT_STORAGE_PROBE_RECEIPT_VERIFY_KEY_SHA256",
        "PILOT_ACCEPTANCE_CAMPAIGN_ID",
        "validate_probe_prefix",
        "aws_kz()",
        "--endpoint-url",
        "--region",
        "--no-cli-pager",
        "probe-receipt-final.sig",
        "storage-probe-authority.verified",
    ):
        assert phrase in deployment

    listings = _continued_commands(
        deployment,
        "s3api list-object-versions",
    )
    downloads = _continued_commands(deployment, "s3api get-object")
    s3_commands = _continued_commands(deployment, "s3api ")
    assert listings
    assert downloads
    assert s3_commands
    assert all("aws_kz" in command for command in s3_commands)
    assert "aws --profile" not in deployment
    assert all(
        "--max-keys 100" in command
        and "--no-paginate" in command
        for command in listings
    )
    assert "--max-items" not in deployment
    assert "--page-size" not in deployment
    assert '"IsTruncated"' in deployment
    assert all("--range" in command for command in downloads)
    assert deployment.index("probe-receipt-final.sig") < deployment.index(
        "delete_probe_version evidence",
    )


def test_retention_measurement_preserves_each_cycle_and_stays_blocked() -> None:
    deployment = (DOCS / "deployment_runbook.md").read_text()

    for phrase in (
        "PILOT_RETENTION_CYCLE_ID",
        'cycle_dir="${PILOT_RETENTION_SNAPSHOT_ROOT}/${PILOT_RETENTION_CYCLE_ID}"',
        'test ! -e "${cycle_dir}"',
        "cycle-receipt.sig",
        "PILOT_RETENTION_RECEIPT_MAX_BYTES_PER_CYCLE",
        "cycle_bytes_before_signature",
        "cycle_files_before_signature",
        "cycle_bytes",
        "cycle_files",
        "PILOT_RETENTION_RECEIPT_ROOT_QUOTA_BYTES",
        "PILOT_RETENTION_FORECAST_CYCLES",
        "orphan-version instrumentation remains BLOCKED",
    ):
        assert phrase in deployment
    assert "PILOT_RETENTION_SNAPSHOT_DIR" not in deployment
    assert deployment.index("cycle_bytes_before_signature") < deployment.index(
        '-sign "${PILOT_RETENTION_RECEIPT_SIGNING_KEY}"',
    )
    assert deployment.index("cycle_bytes") < deployment.index(
        "receipt_root_bytes",
    )


def test_audit_receipt_growth_wording_matches_irreducible_roots_policy() -> None:
    deployment = (DOCS / "deployment_runbook.md").read_text()
    limits = (DOCS / "known_limits.md").read_text()

    assert "no monotonic queue, spool, evidence, preview, audit, or receipt growth" not in deployment
    assert "bounded and forecasted audit receipt-root growth" in deployment
    assert "aggregate retention steady state remains unproven" in limits


def test_optional_overlay_shutdown_does_not_render_absent_overlays() -> None:
    deployment = (DOCS / "deployment_runbook.md").read_text()
    stop_section = deployment.split(
        "## Credential rotation, stop, and rollback",
        maxsplit=1,
    )[1].split("Rollback only", maxsplit=1)[0]

    for selection in (
        "PILOT_RUNTIME_OVERLAY_SELECTED",
        "PILOT_TELEGRAM_OVERLAY_SELECTED",
        "PILOT_ACCEPTANCE_OVERLAY_SELECTED",
    ):
        assert re.search(
            rf'if \[ "\$\{{{selection}:-false\}}" = true \]; then',
            stop_section,
        )
    assert "docker compose -f deploy/pilot/docker-compose.yml down" in stop_section


def test_pending_acceptance_commands_match_current_v3_parser_contract() -> None:
    deployment = (DOCS / "deployment_runbook.md").read_text()
    ready = (DOCS / "ready_to_start.md").read_text()
    replay_source = (ROOT / "scripts" / "pilot" / "replay_20.py").read_text()
    replay_tree = ast.parse(replay_source)
    parser_options = {
        node.args[0].value
        for node in ast.walk(replay_tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "add_argument"
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
        and node.args[0].value.startswith("--")
    }

    assert "NON_EXECUTABLE_V2_REFERENCE" not in ready
    assert "BLOCKED — NON-EXECUTABLE" not in ready
    assert "Compose runtime activation is **BLOCKED**" in deployment
    for gate, duration in (("8", "28800"), ("72", "259200")):
        marker = f"## Pending V3 {gate}-hour target command"
        section = ready.split(marker, maxsplit=1)[1].split("\n## ", maxsplit=1)[0]
        replay = section.split(
            "uv run python scripts/pilot/replay_20.py",
            maxsplit=1,
        )[1].split(
            "uv run python scripts/pilot/acceptance_report.py",
            maxsplit=1,
        )[0]
        documented_options = re.findall(
            r"(?m)^\s+(--[a-z0-9-]+)(?:\s|$)",
            replay,
        )

        assert set(documented_options) <= parser_options
        assert replay.count("--acceptance-source-profile-attestation ") == 3
        assert replay.count("--acceptance-source-profile-signature ") == 3
        assert replay.count("--acceptance-launch-nonce ") == 3
        assert (
            f"export PILOT_ACCEPTANCE_STATE_PATH="
            f"/srv/kuzet/acceptance-authority/{gate}h"
            in section
        )
        assert (
            f"export PILOT_ACCEPTANCE_PROOF_PATH="
            f"/srv/kuzet/acceptance-proofs/{gate}h"
            in section
        )
        for variable, argument in (
            ("PILOT_ACCEPTANCE_CHANNEL_PATH", "--acceptance-channel-dir"),
            ("PILOT_ACCEPTANCE_CAPTURE_PATH", "--acceptance-capture-dir"),
            ("PILOT_ACCEPTANCE_SNAPSHOT_PATH", "--acceptance-snapshot-dir"),
            ("PILOT_ACCEPTANCE_PROOF_PATH", "--acceptance-v3-proof-dir"),
        ):
            assert f"export {variable}=" in section
            assert f'{argument} "${variable}"' in replay
        assert (
            '--acceptance-v3-state '
            '"$PILOT_ACCEPTANCE_STATE_PATH/authority.sqlite3"'
            in replay
        )
        assert "authority-v3.sqlite3" not in section
        for required_once in (
            "--acceptance-transition-journal ",
            "--acceptance-channel-dir ",
            "--acceptance-source-secrets-root ",
            "--acceptance-native-projection-dir ",
            "--acceptance-work-projection-dir ",
            "--acceptance-first-runtime-epoch ",
            "--acceptance-module-gates-sha256 ",
            "--controller-image-id-sha256 ",
            "--controller-image-config-sha256 ",
            "--controller-code-sha256 ",
            "--acceptance-run-signing-key ",
            "--acceptance-capture-dir ",
            "--acceptance-snapshot-dir ",
            "--acceptance-v3-proof-dir ",
            "--acceptance-v3-state ",
            "--acceptance-operational-limits ",
            "--acceptance-operational-evidence ",
            "--acceptance-repository-boundary ",
            "--out-v3-result ",
        ):
            assert replay.count(required_once) == 1, required_once
        assert f"--duration-seconds {duration}" in replay
        assert (
            "PENDING external NVIDIA/site\nexecution — NOT RUN"
            in section
        )


def test_model_build_and_cloud_verification_claims_are_fail_closed() -> None:
    deployment = (DOCS / "deployment_runbook.md").read_text()
    limits = (DOCS / "known_limits.md").read_text()
    build_section = deployment.split(
        "For each rights-cleared ONNX artifact",
        maxsplit=1,
    )[1].split("## Render every selected configuration", maxsplit=1)[0]

    assert "MODEL ENGINE BUILD BLOCKED" in build_section
    assert "uv run" not in build_section
    assert "PENDING implementation review and external execution" in deployment
    assert "No full-suite pass is claimed for this revision" in limits


def test_rendered_compose_inventory_has_exact_redaction_and_digest_steps() -> None:
    deployment = (DOCS / "deployment_runbook.md").read_text()

    for phrase in (
        "PILOT_COMPOSE_CAMPAIGN_ID",
        "REPLACE_WITH_EXACT_SIGNED_CAMPAIGN_ID",
        "*REPLACE_WITH*",
        '*[!A-Za-z0-9._-]*',
        '"campaign_id": sys.argv[3]',
        '"compose": redact(payload)',
        "compose-render.raw.json",
        "compose-render.redacted.json",
        "compose-render.redacted.sha256",
        "os.replace",
        "raw_path.unlink",
    ):
        assert phrase in deployment


def test_compose_campaign_component_rejects_dot_paths() -> None:
    deployment = (DOCS / "deployment_runbook.md").read_text()
    validator = deployment.split(
        "export PILOT_COMPOSE_CAMPAIGN_ID="
        "REPLACE_WITH_EXACT_SIGNED_CAMPAIGN_ID\n",
        maxsplit=1,
    )[1].split(
        "export PILOT_COMPOSE_RECEIPT_ROOT=",
        maxsplit=1,
    )[0]
    script = 'PILOT_COMPOSE_CAMPAIGN_ID="$1"\n' + validator

    for unsafe in (".", ".."):
        result = subprocess.run(
            ("bash", "-c", script, "campaign-validator", unsafe),
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0, unsafe
    accepted = subprocess.run(
        (
            "bash",
            "-c",
            script,
            "campaign-validator",
            "site-1.campaign_2026-07-31",
        ),
        check=False,
        capture_output=True,
        text=True,
    )
    assert accepted.returncode == 0, accepted.stderr


def test_handover_manifest_item_rows_are_unique() -> None:
    manifest = (DOCS / "handover_manifest.md").read_text()
    items = [
        cells[1].strip()
        for line in manifest.splitlines()
        if line.startswith("|")
        and len(cells := line.split("|")) >= 3
        and cells[1].strip() not in {"Item", "---"}
    ]

    assert len(items) == len(set(items))
