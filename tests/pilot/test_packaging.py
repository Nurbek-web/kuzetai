from __future__ import annotations

import re
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "deploy" / "pilot"
BASE = DEPLOY / "docker-compose.yml"

OVERLAYS = {
    "runtime": DEPLOY / "docker-compose.runtime.yml",
    "acceptance": DEPLOY / "docker-compose.acceptance.yml",
    "telegram": DEPLOY / "docker-compose.telegram.yml",
    "backup": DEPLOY / "docker-compose.backup.yml",
    "restore": DEPLOY / "docker-compose.restore.yml",
    "admin": DEPLOY / "docker-compose.admin.yml",
}

CAMERA_RTSP_SECRETS = tuple(
    f"camera_{number:02d}_rtsp_url" for number in range(1, 21)
)
RUNTIME_COMPOSITION_ARGUMENTS = {
    "--database-url-secret": "/run/secrets/runtime_database_url",
    "--object-store-access-key-secret": (
        "/run/secrets/runtime_object_store_access_key"
    ),
    "--object-store-secret-key-secret": (
        "/run/secrets/runtime_object_store_secret_key"
    ),
    "--object-store-region": (
        "${PILOT_RUNTIME_OBJECT_STORE_REGION:"
        "?set-reviewed-object-store-region}"
    ),
}


def _compose(path: Path) -> dict[str, object]:
    payload = yaml.safe_load(path.read_text())
    assert isinstance(payload, dict), path
    return payload


def _services(path: Path) -> dict[str, object]:
    services = _compose(path).get("services")
    assert isinstance(services, dict), path
    return services


def _secret_map(service: dict[str, object]) -> dict[str, str]:
    result: dict[str, str] = {}
    secrets = service.get("secrets", ())
    assert isinstance(secrets, list)
    for item in secrets:
        if isinstance(item, str):
            result[item] = item
        else:
            assert isinstance(item, dict)
            result[str(item["target"])] = str(item["source"])
    return result


def _command_map(service: dict[str, object]) -> dict[str, str]:
    command = service.get("command")
    assert isinstance(command, list)
    result: dict[str, str] = {}
    for item in command:
        assert isinstance(item, str) and item.startswith("--")
        name, separator, value = item.partition("=")
        assert separator == "="
        result[name] = value
    return result


def _render_only_runtime_command(path: Path) -> dict[str, str]:
    compose = _compose(path)
    command = compose.get("x-kuzet-render-only-runtime-command")
    assert isinstance(command, list)
    return _command_map({"command": command})


def test_core_compose_has_no_optional_acceptance_or_notification_inputs() -> None:
    content = BASE.read_text()
    services = _services(BASE)

    assert "acceptance-controller" not in services
    assert "notifications" not in services
    for forbidden in (
        "PILOT_ACCEPTANCE_",
        "PILOT_TELEGRAM_",
        "PILOT_NOTIFICATION_EGRESS_NETWORK",
        "telegram_bot_token",
        "telegram_chat_id",
        "acceptance_controller_token",
        "acceptance-loopback",
    ):
        assert forbidden not in content


def test_every_optional_operational_surface_is_an_explicit_overlay() -> None:
    for name, path in OVERLAYS.items():
        assert path.is_file(), name
        assert _services(path), name

    assert set(_services(OVERLAYS["runtime"])) == {"api", "runtime"}
    assert set(_services(OVERLAYS["acceptance"])) == {"acceptance-controller"}
    assert set(_services(OVERLAYS["telegram"])) == {"api", "notifications"}
    assert set(_services(OVERLAYS["backup"])) == {"backup"}
    assert set(_services(OVERLAYS["restore"])) == {"restore"}
    assert set(_services(OVERLAYS["admin"])) == {"admin-bootstrap"}


def test_runtime_overlay_is_one_shared_bounded_nvidia_service() -> None:
    content = OVERLAYS["runtime"].read_text()
    runtime = _services(OVERLAYS["runtime"])["runtime"]
    assert isinstance(runtime, dict)

    assert "sha256:${PILOT_RUNTIME_IMAGE_SHA256" in str(runtime["image"])
    assert runtime["read_only"] is True
    assert runtime["cap_drop"] == ["ALL"]
    assert runtime["pids_limit"] > 0
    assert runtime["mem_limit"]
    assert runtime["cpus"]
    assert runtime["gpus"] == [
        {
            "driver": "nvidia",
            "device_ids": [
                "${PILOT_RUNTIME_GPU_UUID:"
                "?set-reviewed-single-GPU-UUID}"
            ],
            "capabilities": ["gpu"],
        }
    ]
    for network in ("camera-lan", "control", "data", "storage-egress"):
        assert network in runtime["networks"]
    for phrase in (
        "create_host_path: false",
        "runtime-spool",
        "runtime-journal",
        "runtime-preview",
        "runtime_database_url",
        "runtime_object_store_access_key",
        "runtime_object_store_secret_key",
    ):
        assert phrase in content
    spool_mounts = [
        mount
        for mount in runtime["volumes"]
        if isinstance(mount, dict)
        and mount.get("source")
        == (
            "${PILOT_RUNTIME_SPOOL_PATH:"
            "?set-finite-encrypted-runtime-spool-path}"
        )
    ]
    assert spool_mounts == [
        {
            "type": "bind",
            "source": (
                "${PILOT_RUNTIME_SPOOL_PATH:"
                "?set-finite-encrypted-runtime-spool-path}"
            ),
            "target": "/srv/kuzet/evidence-spool",
            "read_only": False,
            "bind": {"create_host_path": False},
        }
    ]
    assert "/var/run/docker.sock" not in content
    assert "one shared" in content.casefold()


def test_runtime_overlay_is_mechanically_render_only_and_never_restarts() -> None:
    compose = _compose(OVERLAYS["runtime"])
    runtime = _services(OVERLAYS["runtime"])["runtime"]
    assert isinstance(runtime, dict)

    assert runtime["entrypoint"] == ["/bin/sh", "-eu", "-c"]
    assert runtime["restart"] == "no"
    blocker = runtime["command"]
    assert isinstance(blocker, list) and len(blocker) == 1
    assert "BLOCKED" in blocker[0]
    assert "exit 78" in blocker[0]
    assert "production_main" not in repr(
        (runtime["entrypoint"], runtime["command"])
    )
    assert compose["x-kuzet-render-only-runtime-entrypoint"] == [
        "python3",
        "-m",
        "protector.pilot.runtime.production_main",
    ]
    dockerfile = (DEPLOY / "Dockerfile.runtime").read_text(encoding="utf-8")
    assert (
        'ENTRYPOINT ["python3", "-m", '
        '"protector.pilot.runtime.production_main"]'
        in dockerfile
    )
    intended = compose["x-kuzet-render-only-runtime-command"]
    assert isinstance(intended, list)
    assert "--site-id=${PILOT_SITE_ID:?set-authoritative-site-id}" in intended

    blocked = subprocess.run(
        [*runtime["entrypoint"], *runtime["command"]],
        check=False,
        capture_output=True,
        text=True,
    )
    assert blocked.returncode == 78
    assert 0 < len(blocked.stderr.encode("utf-8")) <= 256
    assert "BLOCKED" in blocked.stderr


def test_runtime_overlay_passes_every_current_production_entrypoint_argument() -> None:
    compose = _compose(OVERLAYS["runtime"])
    assert compose["x-kuzet-render-only-runtime-entrypoint"] == [
        "python3",
        "-m",
        "protector.pilot.runtime.production_main",
    ]
    command = _render_only_runtime_command(OVERLAYS["runtime"])
    assert set(command) == {
        "--site-id",
        "--site-config",
        "--site-config-sha256",
        "--runtime-manifest",
        "--runtime-manifest-sha256",
        "--measured-capacity-report",
        "--measured-capacity-sha256",
        "--measured-capacity-signature",
        "--capacity-authority-public-key",
        "--runtime-image-id-sha256",
        "--runtime-image-config-sha256",
        "--runtime-code-sha256",
        "--mount-contract-sha256",
        "--runtime-launch-nonce",
        "--control-plane-url",
        "--machine-token-file",
        *RUNTIME_COMPOSITION_ARGUMENTS,
    }
    for name, target in RUNTIME_COMPOSITION_ARGUMENTS.items():
        assert command[name] == target


def test_runtime_overlay_mount_targets_match_the_runtime_manifest_template() -> None:
    runtime = _services(OVERLAYS["runtime"])["runtime"]
    assert isinstance(runtime, dict)
    command = _render_only_runtime_command(OVERLAYS["runtime"])
    volumes = runtime["volumes"]
    assert isinstance(volumes, list)

    model_mounts = [
        mount
        for mount in volumes
        if isinstance(mount, dict)
        and mount.get("source")
        == (
            "${PILOT_RUNTIME_MODEL_PATH:"
            "?set-reviewed-model-and-engine-directory}"
        )
    ]
    assert model_mounts == [
        {
            "type": "bind",
            "source": (
                "${PILOT_RUNTIME_MODEL_PATH:"
                "?set-reviewed-model-and-engine-directory}"
            ),
            "target": "/run/runtime",
            "read_only": True,
            "bind": {"create_host_path": False},
        }
    ]
    assert _secret_map(runtime)["machine_token"] == "runtime_machine_token"
    assert "runtime_machine_token" not in _secret_map(runtime)
    assert command["--machine-token-file"] == "/run/secrets/machine_token"

    template = _compose(ROOT / "configs" / "models" / "person_primary.yaml")
    assert template["nvinfer_config_path"] == "/run/runtime/person_primary.txt"


def test_runtime_composition_entrypoint_consumes_and_binds_every_authority() -> None:
    runtime = _services(OVERLAYS["runtime"])["runtime"]
    assert isinstance(runtime, dict)
    command = _render_only_runtime_command(OVERLAYS["runtime"])
    source = (
        ROOT / "protector" / "pilot" / "runtime" / "production_main.py"
    ).read_text()

    for name, value in RUNTIME_COMPOSITION_ARGUMENTS.items():
        assert command[name] == value
        assert f'"{name}"' in source
    for required_composition in (
        "claim_runtime_writer(",
        "load_runtime_configuration(",
        "bind_runtime_repository(",
        "build_production_event_pipeline(",
        "pipeline.bind_observation_source(runtime)",
        "worker.start()",
        "runtime.start(active_site)",
        "runtime.stop(preserve_observations=True)",
        "runtime.finish_observation_drain()",
    ):
        assert required_composition in source


def test_runtime_image_installs_hash_locked_composition_and_evidence_tools() -> None:
    content = (DEPLOY / "Dockerfile.runtime").read_text()

    for phrase in (
        "api-requirements.lock",
        "--require-hashes",
        "import boto3, prometheus_client, psycopg, pydantic, sqlalchemy, yaml",
        "command -v ffmpeg",
        "command -v ffprobe",
        "command -v gst-inspect-1.0",
        "command -v openssl",
        "import gi",
        "import pyds",
        "USER 10001:10001",
    ):
        assert phrase in content
    assert "nvidia-smi" not in content


def test_runtime_overlay_extends_api_with_read_only_preview_identity_only() -> None:
    services = _services(OVERLAYS["runtime"])
    api = services["api"]
    runtime = services["runtime"]
    assert isinstance(api, dict)
    assert isinstance(runtime, dict)

    assert api["environment"] == {
        "PILOT_SITE_CONFIG_PATH": "/run/config/site.yaml",
        "PILOT_SITE_CONFIG_SHA256": (
            "${PILOT_SITE_CONFIG_SHA256:?set-reviewed-site-config-sha256}"
        ),
        "PILOT_PREVIEW_OBJECT_STORE_ACCESS_KEY_FILE": (
            "/run/secrets/preview_object_store_access_key"
        ),
        "PILOT_PREVIEW_OBJECT_STORE_SECRET_KEY_FILE": (
            "/run/secrets/preview_object_store_secret_key"
        ),
        "PILOT_PREVIEW_OBJECT_STORE_REGION": (
            "${PILOT_PREVIEW_OBJECT_STORE_REGION:"
            "?set-reviewed-object-store-region}"
        ),
    }
    assert api["secrets"] == [
        "preview_object_store_access_key",
        "preview_object_store_secret_key",
    ]
    assert api["networks"] == {"storage-egress": {}}
    assert api["volumes"] == [
        {
            "type": "bind",
            "source": "${PILOT_SITE_CONFIG_PATH:?set-reviewed-site-config-path}",
            "target": "/run/config/site.yaml",
            "read_only": True,
            "bind": {"create_host_path": False},
        }
    ]
    assert not {
        "runtime_object_store_access_key",
        "runtime_object_store_secret_key",
        "object_store_access_key",
        "object_store_secret_key",
    }.intersection(api["secrets"])
    assert {
        "runtime_database_url",
        "runtime_object_store_access_key",
        "runtime_object_store_secret_key",
    }.issubset(set(_secret_map(runtime).values()))


def test_runtime_mounts_exactly_twenty_canonical_external_camera_secrets() -> None:
    compose = _compose(OVERLAYS["runtime"])
    runtime = _services(OVERLAYS["runtime"])["runtime"]
    assert isinstance(runtime, dict)
    secrets = _secret_map(runtime)

    mounted = {
        target: source
        for target, source in secrets.items()
        if target.endswith("_rtsp_url")
    }
    assert mounted == {name: name for name in CAMERA_RTSP_SECRETS}
    top_level = compose["secrets"]
    assert isinstance(top_level, dict)
    for name in CAMERA_RTSP_SECRETS:
        assert top_level[name] == {"external": True}


def test_reviewed_runtime_config_must_map_one_to_one_to_camera_secret_files() -> None:
    deployment = (ROOT / "docs" / "pilot" / "deployment_runbook.md").read_text()

    for name in CAMERA_RTSP_SECRETS:
        assert f"docker_secret: /run/secrets/{name}" in deployment
    assert (
        "RTSP credentials through environment variables are forbidden"
        in deployment
    )


def test_acceptance_overlay_packages_protected_v3_without_docker_socket() -> None:
    content = OVERLAYS["acceptance"].read_text()
    service = _services(OVERLAYS["acceptance"])["acceptance-controller"]
    assert isinstance(service, dict)

    assert "create_production_acceptance_controller_v3_app" in content
    assert "PILOT_ACCEPTANCE_GATE" in content
    assert "acceptance-snapshot" in content
    assert "acceptance-proof" in content
    assert "acceptance-channel" in content
    assert "/var/run/docker.sock" not in content
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    environment = service["environment"]
    assert isinstance(environment, dict)
    assert environment["PILOT_ACCEPTANCE_CAPTURE_DIR"] == (
        "/var/lib/kuzet/acceptance-capture"
    )
    volumes = service["volumes"]
    assert isinstance(volumes, list)
    targets = {
        item["target"]: item["source"]
        for item in volumes
        if isinstance(item, dict)
    }
    assert targets["/var/lib/kuzet/acceptance/authority.sqlite3"] == (
        "${PILOT_ACCEPTANCE_STATE_PATH:"
        "?set-private-finite-acceptance-state-path}/authority.sqlite3"
    )
    assert targets["/var/lib/kuzet/acceptance-proof"] == (
        "${PILOT_ACCEPTANCE_PROOF_PATH:"
        "?set-private-finite-gate-proof-path}"
    )
    assert targets["/var/lib/kuzet/acceptance-snapshot"] == (
        "${PILOT_ACCEPTANCE_SNAPSHOT_PATH:"
        "?set-private-finite-gate-snapshot-path}"
    )
    assert targets["/var/lib/kuzet/acceptance-channel"] == (
        "${PILOT_ACCEPTANCE_CHANNEL_PATH:"
        "?set-private-launch-bound-channel-path}"
    )
    assert targets["/var/lib/kuzet/acceptance-capture"] == (
        "${PILOT_ACCEPTANCE_CAPTURE_PATH:"
        "?set-private-finite-acceptance-capture-path}"
    )
    assert targets["/var/lib/kuzet/acceptance-capture"] != targets[
        "/var/lib/kuzet/acceptance-channel"
    ]
    dockerfile = (DEPLOY / "Dockerfile.api").read_text()
    for target in (
        "/var/lib/kuzet/acceptance-capture",
        "/var/lib/kuzet/acceptance-channel",
        "/var/lib/kuzet/acceptance-snapshot",
    ):
        assert target in dockerfile


def test_acceptance_package_factory_route_and_runner_are_not_misrepresented() -> None:
    compose = _services(OVERLAYS["acceptance"])["acceptance-controller"]
    assert isinstance(compose, dict)
    command = compose["command"]
    assert isinstance(command, list)
    controller = (
        ROOT / "protector" / "pilot" / "api" / "acceptance_controller.py"
    ).read_text()
    runner = (ROOT / "scripts" / "pilot" / "replay_20.py").read_text()
    runbook = (ROOT / "docs" / "pilot" / "deployment_runbook.md").read_text()
    factory = "create_production_acceptance_controller_v3_app"
    route = "/api/internal/acceptance/v3/collectors/{collector_id}/finalize"

    assert command[0].endswith(f":{factory}")
    assert f"def {factory}" in controller
    assert route in controller
    assert "authority=legacy_authority" in controller
    assert "v3_authority=controller" in controller
    assert '"/api/internal/acceptance/start"' in runner
    assert '"/api/internal/acceptance/finalize"' in runner
    assert "/api/internal/acceptance/v3/collectors/" in runner
    assert 'f"{encoded_collector}/finalize"' in runner
    assert "collector.finalize_v3(" in runner
    assert "CollectorBoundAcceptanceControllerV3(" not in runner
    assert route in runbook
    assert "retained V2" in runbook
    assert "collection routes" in runbook
    assert "PENDING external NVIDIA/site execution — NOT RUN" in runbook


def test_every_overlay_bind_is_explicit_and_cannot_create_a_host_path() -> None:
    for name, path in OVERLAYS.items():
        for service_name, service in _services(path).items():
            assert isinstance(service, dict), (name, service_name)
            for volume in service.get("volumes", ()):
                assert isinstance(volume, dict), (name, service_name, volume)
                assert volume["type"] == "bind", (name, service_name, volume)
                assert volume["bind"] == {"create_host_path": False}, (
                    name,
                    service_name,
                    volume,
                )


def test_every_base_bind_is_long_syntax_and_cannot_create_a_host_path() -> None:
    compose = _compose(BASE)
    declared_volumes = compose["volumes"]
    assert isinstance(declared_volumes, dict)
    for service_name, service in _services(BASE).items():
        assert isinstance(service, dict), service_name
        for volume in service.get("volumes", ()):
            if isinstance(volume, str):
                source = volume.partition(":")[0]
                assert source in declared_volumes, (service_name, volume)
                continue
            assert isinstance(volume, dict), (service_name, volume)
            assert volume["type"] == "bind", (service_name, volume)
            assert volume["bind"] == {"create_host_path": False}, (
                service_name,
                volume,
            )


def test_overlay_services_are_hardened_and_have_no_container_control_mount() -> None:
    for name, path in OVERLAYS.items():
        content = path.read_text()
        assert "network_mode: host" not in content
        assert "privileged: true" not in content
        assert "/var/run/docker.sock" not in content
        for service_name, service in _services(path).items():
            if service_name == "api":
                continue
            assert service["read_only"] is True, (name, service_name)
            assert service["cap_drop"] == ["ALL"], (name, service_name)
            assert service["pids_limit"] > 0, (name, service_name)
            assert service["mem_limit"], (name, service_name)
            assert service["cpus"], (name, service_name)


def test_telegram_egress_exists_only_in_explicit_approved_overlay() -> None:
    content = OVERLAYS["telegram"].read_text()

    assert "PILOT_TELEGRAM_CUSTOMER_APPROVED" in content
    assert "PILOT_TELEGRAM_NETWORK_APPROVED" in content
    assert "PILOT_NOTIFICATION_EGRESS_NETWORK" in content
    assert "telegram_bot_token" in content
    assert "telegram_chat_id" in content


def test_machine_credentials_are_route_scoped_and_never_aliased() -> None:
    base = _compose(BASE)
    base_services = _services(BASE)
    api = base_services["api"]
    prometheus = base_services["prometheus"]
    runtime = _services(OVERLAYS["runtime"])["runtime"]
    telegram_services = _services(OVERLAYS["telegram"])
    telegram_api = telegram_services["api"]
    notifications = telegram_services["notifications"]
    for service in (api, prometheus, runtime, telegram_api, notifications):
        assert isinstance(service, dict)

    assert _secret_map(api) == {
        "database_url": "database_url",
        "session_secret": "session_secret",
        "totp_encryption_key": "totp_encryption_key",
        "runtime_machine_token": "runtime_machine_token",
        "monitoring_machine_token": "monitoring_machine_token",
        "evidence_link_signing_secret": "evidence_link_signing_secret",
    }
    assert _secret_map(prometheus) == {
        "monitoring_machine_token": "monitoring_machine_token"
    }
    assert _secret_map(runtime)["machine_token"] == "runtime_machine_token"
    assert _secret_map(telegram_api) == {
        "notification_machine_token": "notification_machine_token"
    }
    assert _secret_map(notifications)["machine_token"] == (
        "notification_machine_token"
    )

    production = (ROOT / "protector" / "pilot" / "api" / "production.py").read_text()
    application = (ROOT / "protector" / "pilot" / "api" / "app.py").read_text()
    dependencies = (
        ROOT / "protector" / "pilot" / "api" / "dependencies.py"
    ).read_text()
    internal_routes = (
        ROOT / "protector" / "pilot" / "api" / "routes_internal.py"
    ).read_text()
    for secret in ("runtime_machine_token", "monitoring_machine_token"):
        assert f'_read_secret("{secret}")' in production
    assert (
        '_read_optional_secret("notification_machine_token")'
        in production
    )
    assert 'machine_token=_read_secret("machine_token")' not in production
    assert "evidence link signing secret must not be a machine token" in production
    assert application.count("Depends(require_monitoring_machine_auth)") == 4
    assert (
        internal_routes.count(
            "dependencies=[Depends(require_runtime_machine_auth)]"
        )
        == 2
    )
    assert "credential: Annotated[str, Depends(get_machine_credential)]" in (
        internal_routes
    )
    assert "scoped machine tokens must be distinct" in application
    assert 'role="notification" if payload.publisher == "notifications"' in (
        internal_routes
    )
    for dependency in (
        "def require_runtime_machine_auth",
        "def require_monitoring_machine_auth",
        "def authorize_machine_role",
    ):
        assert dependency in dependencies
    assert "runtime_machine_token" in base["secrets"]
    assert "monitoring_machine_token" in base["secrets"]
    assert "machine_token" not in base["secrets"]
    prometheus_config = (DEPLOY / "prometheus.yml").read_text()
    assert "/run/secrets/monitoring_machine_token" in prometheus_config
    assert "/run/secrets/machine_token" not in prometheus_config


def test_telegram_uses_one_shared_link_secret_but_distinct_machine_credential() -> None:
    compose = _compose(OVERLAYS["telegram"])
    service = _services(OVERLAYS["telegram"])["notifications"]
    assert isinstance(service, dict)
    assert _secret_map(service) == {
        "database_url": "notification_database_url",
        "machine_token": "notification_machine_token",
        "evidence_link_signing_secret": "evidence_link_signing_secret",
        "telegram_bot_token": "notification_telegram_bot_token",
        "telegram_chat_id": "notification_telegram_chat_id",
    }
    top_level = compose["secrets"]
    assert isinstance(top_level, dict)
    assert set(top_level) == {
        "notification_database_url",
        "notification_machine_token",
        "evidence_link_signing_secret",
        "notification_telegram_bot_token",
        "notification_telegram_chat_id",
    }
    assert all(value == {"external": True} for value in top_level.values())
    assert "evidence_link_signing_secret" != "notification_machine_token"
    assert "notification_evidence_link_secret" not in compose


def test_runtime_database_role_is_bootstrapped_without_broad_dml() -> None:
    compose = _compose(BASE)
    bootstrap_service = _services(BASE)["role-bootstrap"]
    assert isinstance(bootstrap_service, dict)
    source = (ROOT / "scripts" / "pilot" / "bootstrap_roles.py").read_text()

    assert "CREATE ROLE kuzet_runtime LOGIN NOSUPERUSER" in source
    assert "kuzet_runtime" in source
    assert "--runtime-password-secret" in source
    assert (
        "--runtime-password-secret=/run/secrets/runtime_database_password"
        in bootstrap_service["command"]
    )
    assert "runtime_database_password" in _secret_map(bootstrap_service)
    assert compose["secrets"]["runtime_database_password"] == {"external": True}
    assert "GRANT CONNECT ON DATABASE" in source
    assert "GRANT USAGE ON SCHEMA public" in source
    assert "REVOKE kuzet_owner FROM kuzet_api, kuzet_runtime, kuzet_retention" in source
    assert "NOREPLICATION NOBYPASSRLS" in source
    assert "pg_auth_members" in source
    assert "_assert_service_roles_are_unprivileged" in source
    assert "SELECT count(*) = 3" in source
    assert "owned_database.datdba = role.oid" in source
    assert "owned_schema.nspowner = role.oid" in source
    assert "owned_relation.relowner = role.oid" in source
    assert "owned_routine.proowner = role.oid" in source
    assert "REVOKE %I FROM %I" in source
    membership_guard = source[
        source.index("SELECT count(*) = 3") :
        source.index("pilot service roles are not least privilege")
    ]
    for service_role in (
        "kuzet_api",
        "kuzet_runtime",
        "kuzet_retention",
    ):
        assert service_role in membership_guard
    for broad_grant in (
        "GRANT ALL",
        "GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO kuzet_api",
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO kuzet_api",
        "GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO kuzet_runtime",
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO kuzet_runtime",
        "GRANT INSERT ON TABLE candidate_events TO kuzet_runtime",
        "GRANT UPDATE ON TABLE candidate_events TO kuzet_runtime",
        "GRANT DELETE ON TABLE candidate_events TO kuzet_runtime",
    ):
        assert broad_grant not in source
    assert (
        "REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM kuzet_api"
        in source
    )
    direct_table_grants = "\n".join(
        re.findall(
            r"GRANT\s+(?:SELECT|INSERT|UPDATE|DELETE|,|\s)+"
            r"ON TABLE\s+(.*?)\s+TO kuzet_[a-z]+",
            source,
            flags=re.DOTALL,
        )
    )
    assert "preview_publications" not in direct_table_grants
    assert "preview_access_receipts" not in direct_table_grants
    for bounded_function in (
        "public.pilot_get_preview_object_context",
        "public.pilot_prepare_preview_publication",
        "public.pilot_finalize_preview_receipt",
        "public.pilot_claim_preview_receipts_for_retention",
        "public.pilot_finalize_preview_retirement",
        "public.pilot_preview_version_is_protected",
        "public.pilot_prune_preview_access_receipts",
        "public.pilot_retire_expired_preview_intents",
    ):
        assert bounded_function in source
    assert "notification_outbox, delivery_attempts, audit_entries" in source
    assert "GRANT UPDATE ON TABLE sites" not in source


def test_every_production_database_process_attests_its_exact_login_role() -> None:
    api = (ROOT / "protector" / "pilot" / "api" / "production.py").read_text()
    runtime = (
        ROOT / "protector" / "pilot" / "runtime" / "production_main.py"
    ).read_text()
    retention = (
        ROOT / "protector" / "pilot" / "retention_service.py"
    ).read_text()

    assert 'expected_role="kuzet_api"' in api
    assert 'expected_role="kuzet_runtime"' in runtime
    retention_main = retention[retention.index("def main(") :]
    assert retention_main.count('expected_role="kuzet_retention"') == 2
    assert retention_main.index(
        'expected_role="kuzet_retention"'
    ) < retention_main.index("_acquire_retention_lease(")


def test_retention_command_supplies_bounded_preview_reconciliation_contract() -> None:
    retention = _services(BASE)["retention"]
    assert isinstance(retention, dict)
    command = _command_map(retention)

    assert command["--preview-batch-size"] == "1000"
    assert command["--preview-publication-grace-seconds"] == "900"
    assert command["--object-store-region"] == (
        "${PILOT_RETENTION_OBJECT_STORE_REGION:"
        "?set-reviewed-object-store-region}"
    )


def test_runtime_and_retention_object_store_acl_contract_is_explicit() -> None:
    documents = "\n".join(
        (
            (DEPLOY / "NETWORK_POLICY.md").read_text(),
            (ROOT / "docs" / "pilot" / "deployment_runbook.md").read_text(),
            (ROOT / "docs" / "pilot" / "handover_manifest.md").read_text(),
        )
    )

    for action in (
        "s3:GetBucketVersioning",
        "s3:GetLifecycleConfiguration",
        "s3:GetObjectVersion",
        "s3:PutObject",
        "s3:ListBucketVersions",
        "s3:DeleteObjectVersion",
    ):
        assert action in documents
    assert "runtime writer identity" in documents
    assert "retention identity" in documents
    assert "NoncurrentDays=1" in documents
    assert "kms:GenerateDataKey" in documents
    assert "kms:Decrypt" in documents
    network_policy = (DEPLOY / "NETWORK_POLICY.md").read_text()
    runtime_policy = network_policy[
        network_policy.index("The runtime writer identity is separate.") :
        network_policy.index("The retention identity has")
    ]
    assert "s3:GetObjectVersion" not in runtime_policy
    assert "named noncurrent version" in runtime_policy
    assert 's3:if-none-match = "*"' in network_policy
    assert "same-key, different-byte conditional write" in network_policy
    assert "`409`/`412`" in network_policy
    assert "`403`/authorization denial" in network_policy
    assert "original current object and" in network_policy
    assert "storage acceptance is **BLOCKED**" in network_policy


def test_egress_overlays_use_distinct_precreated_external_networks() -> None:
    base = _compose(BASE)
    runtime = _compose(OVERLAYS["runtime"])
    telegram = _compose(OVERLAYS["telegram"])

    assert base["networks"]["storage-egress"]["external"] is True
    assert runtime["networks"]["camera-lan"]["external"] is True
    assert telegram["networks"]["notification-egress"]["external"] is True
    assert "PILOT_CAMERA_NETWORK" in runtime["networks"]["camera-lan"]["name"]
    assert "PILOT_NOTIFICATION_EGRESS_NETWORK" in (
        telegram["networks"]["notification-egress"]["name"]
    )


def test_ops_image_is_digest_pinned_non_root_and_proves_required_tools() -> None:
    content = (DEPLOY / "Dockerfile.ops").read_text()

    assert "FROM --platform=linux/amd64" in content
    assert "@sha256:" in content
    assert "USER 10002:10002" in content
    assert "ops-requirements.lock" in content
    assert "--require-hashes" in content
    assert 'psycopg[binary]==3.3.4' not in content
    assert 'python3 -c "import psycopg"' in content
    assert "ops-package-versions.txt" in content
    for executable in (
        "age",
        "aws",
        "cmp",
        "findmnt",
        "openssl",
        "pg_dump",
        "pg_restore",
        "psql",
        "python3",
        "sha256sum",
        "tar",
    ):
        assert f"command -v {executable}" in content


def test_backup_restore_and_admin_jobs_are_secret_file_only_and_bounded() -> None:
    backup = OVERLAYS["backup"].read_text()
    restore = OVERLAYS["restore"].read_text()
    admin = OVERLAYS["admin"].read_text()

    assert "scripts/pilot/backup.sh" in backup
    assert "backup_database_url" in backup
    assert "backup_object_store_access_key" in backup
    assert "read_only: true" in backup
    assert "restart: \"no\"" in backup

    assert "scripts/pilot/restore.sh" in restore
    assert "restore_database_url" in restore
    assert "fresh-target" in restore
    assert "restore-receipt" in restore
    assert "read_only: true" in restore
    assert "restart: \"no\"" in restore

    assert "scripts/pilot/bootstrap_admin.py" in admin
    for secret in (
        "admin_bootstrap_database_url",
        "admin_bootstrap_username",
        "admin_bootstrap_password",
        "admin_bootstrap_totp",
        "totp_encryption_key",
    ):
        assert secret in admin
    assert "restart: \"no\"" in admin


def test_backup_restore_secret_targets_match_entrypoint_contracts() -> None:
    backup = _services(OVERLAYS["backup"])["backup"]
    restore = _services(OVERLAYS["restore"])["restore"]
    assert isinstance(backup, dict)
    assert isinstance(restore, dict)

    backup_targets = {
        item["target"]: item["source"] for item in backup["secrets"]
    }
    assert backup_targets == {
        "pg_service.conf": "backup_database_url",
        "pgpass": "backup_database_password",
        "backup_age_recipient": "backup_age_recipient",
        "backup_signing_private_key": "backup_signing_private_key",
        "aws_credentials": "backup_object_store_access_key",
        "kz_storage_attestation_public_key": (
            "backup_kz_storage_attestation_public_key"
        ),
        "kz_storage_verifier_record": "backup_kz_storage_verifier_record",
    }

    restore_targets = {
        item["target"]: item["source"] for item in restore["secrets"]
    }
    assert restore_targets == {
        "pg_restore_service.conf": "restore_database_url",
        "pgpass": "restore_database_password",
        "backup_age_identity": "restore_backup_age_identity",
        "backup_age_recipient": "restore_backup_age_recipient",
        "backup_signing_public_key": "restore_backup_signing_public_key",
        "kz_storage_attestation_public_key": (
            "restore_kz_storage_attestation_public_key"
        ),
        "kz_storage_verifier_record": "restore_kz_storage_verifier_record",
        "restore_receipt_signing_private_key": (
            "restore_receipt_signing_private_key"
        ),
        "restore_receipt_signing_public_key": (
            "restore_receipt_signing_public_key"
        ),
    }


def test_deployment_runbook_commands_reference_real_overlays_and_services() -> None:
    deployment = (ROOT / "docs" / "pilot" / "deployment_runbook.md").read_text()

    for name, path in OVERLAYS.items():
        assert path.name in deployment, name
    for service in (
        "runtime",
        "acceptance-controller",
        "notifications",
        "backup",
        "restore",
        "admin-bootstrap",
    ):
        assert service in deployment

    for phrase in (
        "config --quiet",
        "Dockerfile.ops",
        "PILOT_RESTORE_EVIDENCE_NAME",
        "status=verified_fresh_target_restore",
        "PENDING external NVIDIA execution",
        "nvidia-smi --query-gpu=uuid,driver_version",
        "notification-specific PostgreSQL role",
    ):
        assert phrase in deployment
    assert "cp configs/pilot.example.yaml" not in deployment
    assert "install --owner=root --group=root --mode=0440" in deployment


def test_network_policy_includes_api_read_only_preview_egress() -> None:
    policy = (DEPLOY / "NETWORK_POLICY.md").read_text()

    assert "| `storage-egress` | retention, runtime, backup, API preview reader |" in policy
    assert "API preview reader" in policy
    assert "read-only ranged object access" in policy
    for action in (
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:GetBucketVersioning",
        "s3:GetLifecycleConfiguration",
    ):
        assert action in policy
    assert "bucket-level read-only" in policy


def test_handover_inventory_has_hardware_and_per_service_acl_receipts() -> None:
    manifest = (ROOT / "docs" / "pilot" / "handover_manifest.md").read_text()

    for phrase in (
        "Reviewed GPU UUID",
        "NVIDIA driver version",
        "NVIDIA container-toolkit version",
        "Single-GPU Compose binding",
        "API preview DB/S3 ACL receipt",
        "Runtime writer DB/S3 ACL receipt",
        "Retention DB/S3 ACL receipt",
        "Backup DB/S3 ACL receipt",
        "Notification DB/link ACL receipt",
        "Restore DB/storage ACL receipt",
    ):
        assert phrase in manifest


def test_api_image_probes_uvicorn_factories_and_uses_one_proof_path() -> None:
    dockerfile = (DEPLOY / "Dockerfile.api").read_text()
    acceptance = OVERLAYS["acceptance"].read_text()
    ready = (ROOT / "docs" / "pilot" / "ready_to_start.md").read_text()
    proof_path = "/var/lib/kuzet/acceptance-proof"

    for phrase in (
        "command -v openssl",
        "command -v uvicorn",
        "from protector.pilot.api.production import create_production_app",
        (
            "from protector.pilot.api.acceptance_controller import "
            "create_production_acceptance_controller_v3_app"
        ),
    ):
        assert phrase in dockerfile
    assert proof_path in dockerfile
    assert proof_path in acceptance
    assert proof_path in ready
    assert "/var/lib/kuzet/acceptance-proofs" not in dockerfile
    assert "/var/lib/kuzet/acceptance-proofs" not in acceptance
    assert "/var/lib/kuzet/acceptance-proofs" not in ready


def test_runtime_and_api_secret_mounts_correspond_to_fixed_consumers() -> None:
    runtime = _services(OVERLAYS["runtime"])["runtime"]
    api = _services(OVERLAYS["runtime"])["api"]
    assert isinstance(runtime, dict)
    assert isinstance(api, dict)

    runtime_secrets = _secret_map(runtime)
    command = _render_only_runtime_command(OVERLAYS["runtime"])
    assert runtime_secrets["runtime_database_url"] == "runtime_database_url"
    assert runtime_secrets["runtime_object_store_access_key"] == (
        "runtime_object_store_access_key"
    )
    assert runtime_secrets["runtime_object_store_secret_key"] == (
        "runtime_object_store_secret_key"
    )
    for name, target in RUNTIME_COMPOSITION_ARGUMENTS.items():
        assert command[name] == target
        if name.endswith("-secret"):
            assert target.removeprefix("/run/secrets/") in runtime_secrets

    api_secrets = _secret_map(api)
    assert api_secrets == {
        "preview_object_store_access_key": "preview_object_store_access_key",
        "preview_object_store_secret_key": "preview_object_store_secret_key",
    }


def test_merged_runtime_overlay_preserves_core_api_isolation() -> None:
    base_api = _services(BASE)["api"]
    overlay_api = _services(OVERLAYS["runtime"])["api"]
    assert isinstance(base_api, dict)
    assert isinstance(overlay_api, dict)

    base_networks = base_api["networks"]
    overlay_networks = overlay_api["networks"]
    assert isinstance(base_networks, dict)
    assert isinstance(overlay_networks, dict)
    assert set(base_networks) | set(overlay_networks) == {
        "control",
        "data",
        "storage-egress",
    }
    assert "runtime_database_url" not in _secret_map(overlay_api).values()


def test_handover_manifest_separates_local_review_from_target_evidence() -> None:
    manifest = (ROOT / "docs" / "pilot" / "handover_manifest.md").read_text()
    rows = [
        line
        for line in manifest.splitlines()
        if line.startswith("|") and not line.startswith("|---")
    ]
    inventory = [
        row.split("|")[1:-1]
        for row in rows
        if "Status" not in row and "Item" not in row
    ]
    assert len(inventory) >= 40
    locally_reviewed = {
        "V3 runner/controller/finalize-route correspondence implementation review",
        "Runtime-restart append-only execution/epoch/continuation/C2 implementation proof",
    }
    observed_local = {
        columns[0].strip()
        for columns in inventory
        if columns[2].strip() == "REVIEWED LOCALLY; TARGET NOT RUN"
    }
    assert observed_local == locally_reviewed
    assert all(
        columns[2].strip() == (
            "REVIEWED LOCALLY; TARGET NOT RUN"
            if columns[0].strip() in locally_reviewed
            else "PENDING"
        )
        for columns in inventory
    )
