"""Fail-closed production composition for the controlled NVIDIA pilot.

This entrypoint starts the shared graph and durable event path.  It deliberately
does not create acceptance artifacts or infer CUDA/DeepStream/throughput success
from construction alone.
"""

from __future__ import annotations

import argparse
import os
import re
import signal
import stat
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel

from protector.pilot.capacity_acceptance import (
    require_measured_primary_capacity,
)
from protector.pilot.config import SiteConfig
from protector.pilot.gates import (
    MeasuredCapacityReportV1,
    site_config_sha256,
)
from protector.pilot.runtime.deepstream import (
    DeepStreamDataPlane,
    RuntimeModelManifestV1,
    _load_nvidia_bindings,
    _read_reviewed_file,
    _target_runtime_info,
)
from protector.pilot.runtime.production_events import (
    ProductionEventPipeline,
    build_production_event_pipeline,
)
from protector.pilot.runtime.production_repository import (
    bind_runtime_repository,
    claim_runtime_writer,
    load_runtime_configuration,
)
from protector.pilot.storage.db import (
    DatabaseRoleAttestationError,
    create_engine,
    create_session_factory,
    require_sqlalchemy_database_role,
)
from protector.pilot.storage.repositories import PilotRepository
from protector.pilot.telemetry import (
    AsyncRuntimeTelemetryPublisher,
    AuthenticatedTelemetryClient,
    RuntimeTelemetryPublisher,
    TargetResourceMetricsProvider,
    read_machine_token,
)
from protector.pilot.trusted_artifacts import verify_detached_artifact
from protector.pilot.trusted_yaml import StrictYAMLError, load_strict_yaml

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REGION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_NONCE = re.compile(r"^[0-9a-f]{32}$")
_MAX_SECRET_BYTES = 16 * 1024
_MAX_CONFIG_BYTES = 8 * 1024 * 1024
_MAX_CONFIG_NODES = 100_000
_MAX_CONFIG_DEPTH = 96
_JOURNAL_PATH = Path("/var/lib/kuzet/journal/events.sqlite3")
_PREVIEW_WORKSPACE = Path("/var/lib/kuzet/previews")


class ProductionRuntimeError(RuntimeError):
    """The production graph could not retain its reviewed authority."""


def _read_secret(path: Path, *, label: str) -> str:
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or not 0 < metadata.st_size <= _MAX_SECRET_BYTES
        ):
            raise ProductionRuntimeError(f"{label} is unavailable")
        payload = os.read(descriptor, _MAX_SECRET_BYTES + 1)
    except OSError as exc:
        raise ProductionRuntimeError(f"{label} is unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        value = payload.decode("utf-8").strip()
    except UnicodeError as exc:
        raise ProductionRuntimeError(f"{label} is unavailable") from exc
    if (
        not value
        or "\x00" in value
        or "\r" in value
        or "\n" in value
    ):
        raise ProductionRuntimeError(f"{label} is unavailable")
    return value


def _strict_model(
    payload: bytes,
    model: type[BaseModel],
    *,
    label: str,
) -> BaseModel:
    try:
        parsed = load_strict_yaml(
            payload,
            max_bytes=_MAX_CONFIG_BYTES,
            max_nodes=_MAX_CONFIG_NODES,
            max_depth=_MAX_CONFIG_DEPTH,
            require_mapping=True,
        )
        return model.model_validate(parsed)
    except (StrictYAMLError, TypeError, ValueError) as exc:
        raise ProductionRuntimeError(
            f"reviewed {label} is invalid"
        ) from exc


def parse_production_arguments(
    argv: Sequence[str] | None = None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the reviewed Kuzet production pilot data plane",
    )
    parser.add_argument("--site-id", required=True)
    parser.add_argument("--site-config", type=Path, required=True)
    parser.add_argument("--site-config-sha256", required=True)
    parser.add_argument("--runtime-manifest", type=Path, required=True)
    parser.add_argument("--runtime-manifest-sha256", required=True)
    parser.add_argument("--measured-capacity-report", type=Path, required=True)
    parser.add_argument("--measured-capacity-sha256", required=True)
    parser.add_argument("--measured-capacity-signature", type=Path, required=True)
    parser.add_argument("--capacity-authority-public-key", type=Path, required=True)
    parser.add_argument("--runtime-image-id-sha256", required=True)
    parser.add_argument("--runtime-image-config-sha256", required=True)
    parser.add_argument("--runtime-code-sha256", required=True)
    parser.add_argument("--mount-contract-sha256", required=True)
    parser.add_argument("--runtime-launch-nonce", required=True)
    parser.add_argument("--control-plane-url", required=True)
    parser.add_argument("--machine-token-file", type=Path, required=True)
    parser.add_argument("--database-url-secret", type=Path, required=True)
    parser.add_argument(
        "--object-store-access-key-secret",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--object-store-secret-key-secret",
        type=Path,
        required=True,
    )
    parser.add_argument("--object-store-region", required=True)
    return parser.parse_args(argv)


def _validate_argument_identity(arguments: argparse.Namespace) -> None:
    if _IDENTIFIER.fullmatch(arguments.site_id) is None:
        raise ProductionRuntimeError("production site identity is invalid")
    if _NONCE.fullmatch(arguments.runtime_launch_nonce) is None:
        raise ProductionRuntimeError("production launch nonce is invalid")
    if _REGION.fullmatch(arguments.object_store_region) is None:
        raise ProductionRuntimeError("production object-store region is invalid")
    for name in (
        "site_config_sha256",
        "runtime_manifest_sha256",
        "measured_capacity_sha256",
        "runtime_image_id_sha256",
        "runtime_image_config_sha256",
        "runtime_code_sha256",
        "mount_contract_sha256",
    ):
        if _SHA256.fullmatch(getattr(arguments, name)) is None:
            raise ProductionRuntimeError(
                "production reviewed digest is invalid"
            )


def _load_reviewed_inputs(
    arguments: argparse.Namespace,
) -> tuple[SiteConfig, RuntimeModelManifestV1]:
    _validate_argument_identity(arguments)
    site_payload = _read_reviewed_file(
        arguments.site_config,
        expected_sha256=arguments.site_config_sha256,
        label="site configuration",
        max_bytes=_MAX_CONFIG_BYTES,
    )
    manifest_payload = _read_reviewed_file(
        arguments.runtime_manifest,
        expected_sha256=arguments.runtime_manifest_sha256,
        label="runtime manifest",
        max_bytes=_MAX_CONFIG_BYTES,
    )
    verified_capacity = verify_detached_artifact(
        payload_path=arguments.measured_capacity_report,
        signature_path=arguments.measured_capacity_signature,
        trusted_public_key_path=arguments.capacity_authority_public_key,
        expected_payload_sha256=arguments.measured_capacity_sha256,
        max_payload_bytes=_MAX_CONFIG_BYTES,
        label="measured capacity report",
    )
    site = _strict_model(
        site_payload,
        SiteConfig,
        label="site configuration",
    )
    manifest = _strict_model(
        manifest_payload,
        RuntimeModelManifestV1,
        label="runtime manifest",
    )
    capacity = _strict_model(
        verified_capacity.payload,
        MeasuredCapacityReportV1,
        label="measured capacity report",
    )
    assert isinstance(site, SiteConfig)
    assert isinstance(manifest, RuntimeModelManifestV1)
    assert isinstance(capacity, MeasuredCapacityReportV1)
    if (
        manifest.site_id != arguments.site_id
        or len(site.ready_to_start.feeds) != 20
        or site.storage.evidence_prefix.split("/")[-1]
        != arguments.site_id
    ):
        raise ProductionRuntimeError(
            "reviewed production site scope is inconsistent"
        )
    try:
        require_measured_primary_capacity(
            site_config=site,
            runtime_manifest=manifest,
            report=capacity,
            runtime_image_id_sha256=arguments.runtime_image_id_sha256,
            runtime_image_config_sha256=(
                arguments.runtime_image_config_sha256
            ),
            runtime_code_sha256=arguments.runtime_code_sha256,
            mount_contract_sha256=arguments.mount_contract_sha256,
            runtime_manifest_file_sha256=(
                arguments.runtime_manifest_sha256
            ),
        )
    except ValueError as exc:
        raise ProductionRuntimeError(
            "measured production capacity lacks exact bindings or 25% headroom"
        ) from exc
    return site, manifest


def _build_s3_client(
    *,
    site: SiteConfig,
    region: str,
    access_key: str,
    secret_key: str,
) -> Any:
    try:
        import boto3
        from botocore.config import Config

        return boto3.client(
            "s3",
            endpoint_url=str(site.storage.endpoint).rstrip("/"),
            region_name=region,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            config=Config(
                connect_timeout=5,
                read_timeout=30,
                retries={
                    "mode": "standard",
                    "total_max_attempts": 3,
                },
                signature_version="s3v4",
                tcp_keepalive=True,
            ),
        )
    except (ImportError, TypeError, ValueError) as exc:
        raise ProductionRuntimeError(
            "production object-store client is unavailable"
        ) from exc


def _require_database_role(engine: Any) -> None:
    """Fail before mutation unless both PostgreSQL role identities are bounded."""

    try:
        require_sqlalchemy_database_role(
            engine,
            expected_role="kuzet_runtime",
        )
    except DatabaseRoleAttestationError as exc:
        raise ProductionRuntimeError(
            "production database connection is not the restricted runtime role"
        ) from exc


def _preview_context(
    repository: Any,
    *,
    site_id: str,
    reservation: Any,
    evidence: Any,
) -> Any:
    try:
        event_id = UUID(str(evidence.event_id))
        evidence_id = UUID(str(evidence.evidence_id))
        source_epoch = UUID(str(reservation.stream_epoch))
    except (AttributeError, TypeError, ValueError) as exc:
        raise ProductionRuntimeError(
            "production preview identity is invalid"
        ) from exc
    return repository.get_preview_object_context(
        site_id=site_id,
        event_id=event_id,
        evidence_id=evidence_id,
        source_epoch=source_epoch,
    )


def _run_operational_loop(
    *,
    runtime: DeepStreamDataPlane,
    worker: Any,
    loop: Any,
    glib: Any,
    signal_module: Any = signal,
) -> int:
    """Run until an operator signal or a redacted graph/worker failure."""

    def poll_failure() -> bool:
        if runtime.failed_reason is not None or worker.status.failed:
            loop.quit()
            return False
        return True

    glib.timeout_add(250, poll_failure)
    previous_handlers: dict[int, Any] = {}

    def request_shutdown(_signum: int, _frame: Any) -> None:
        loop.quit()

    try:
        for signum in (signal_module.SIGTERM, signal_module.SIGINT):
            previous_handlers[signum] = signal_module.getsignal(signum)
            signal_module.signal(signum, request_shutdown)
        if runtime.failed_reason is None and not worker.status.failed:
            loop.run()
    finally:
        for signum, handler in previous_handlers.items():
            signal_module.signal(signum, handler)
    return int(runtime.failed_reason is not None or worker.status.failed)


def _shutdown_production_components(
    *,
    runtime: DeepStreamDataPlane | None,
    pipeline: ProductionEventPipeline | None,
    worker: Any | None,
    object_client: Any | None,
    engine: Any | None,
) -> None:
    """Quiesce graph, drain finite metadata, then close durable dependencies."""

    if runtime is not None:
        try:
            runtime.stop(preserve_observations=True)
        except BaseException:
            # A graph that did not verifiably reach Gst NULL may still execute
            # callbacks. Retain the worker, journal, clients, and database
            # engine so no callback can use a released dependency.
            raise
    failures: list[BaseException] = []
    if pipeline is not None:
        try:
            pipeline.close()
        except BaseException as exc:
            failures.append(exc)

    worker_alive = bool(
        worker is not None
        and getattr(worker, "thread_alive", True)
    )
    if worker_alive:
        failures.append(
            ProductionRuntimeError(
                "production event worker still owns durable dependencies"
            )
        )
    else:
        if runtime is not None:
            try:
                runtime.finish_observation_drain()
            except BaseException as exc:
                failures.append(exc)
        if object_client is not None:
            close_client = getattr(object_client, "close", None)
            if callable(close_client):
                try:
                    close_client()
                except BaseException as exc:
                    failures.append(exc)
        if engine is not None:
            try:
                engine.dispose()
            except BaseException as exc:
                failures.append(exc)
    if len(failures) == 1:
        raise failures[0]
    if failures:
        raise BaseExceptionGroup(
            "production runtime shutdown failed closed",
            failures,
        )


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_production_arguments(argv)
    engine: Any | None = None
    object_client: Any | None = None
    pipeline: ProductionEventPipeline | None = None
    runtime: DeepStreamDataPlane | None = None
    worker: Any | None = None
    result = 1
    primary: BaseException | None = None
    try:
        mounted_site, runtime_manifest = _load_reviewed_inputs(arguments)
        if runtime_manifest.engine_sha256 is None:
            raise ProductionRuntimeError(
                "mounted runtime manifest has no reviewed engine binding"
            )
        database_url = _read_secret(
            arguments.database_url_secret,
            label="production database authority",
        )
        engine = create_engine(database_url)
        _require_database_role(engine)
        sessions = create_session_factory(engine)
        repository = PilotRepository(sessions)
        runtime_session_id = (
            f"runtime-{arguments.runtime_launch_nonce}-{uuid4().hex}"
        )
        claimed_at = datetime.now(UTC)
        writer_receipt = claim_runtime_writer(
            repository,
            arguments.site_id,
            runtime_session_id,
            claimed_at,
        )
        active_site, compiled_rules = load_runtime_configuration(
            repository,
            writer_receipt,
            expected_frozen_workload_sha256=(
                runtime_manifest.frozen_workload_sha256
            ),
            expected_engine_sha256=runtime_manifest.engine_sha256,
            expected_runtime_manifest_sha256=(
                arguments.runtime_manifest_sha256
            ),
        )
        if (
            active_site != mounted_site
            or site_config_sha256(active_site)
            != writer_receipt.site_config_sha256
        ):
            raise ProductionRuntimeError(
                "mounted site configuration is not the active reviewed revision"
            )
        bound_repository = bind_runtime_repository(
            repository=repository,
            writer_receipt=writer_receipt,
        )
        object_client = _build_s3_client(
            site=active_site,
            region=arguments.object_store_region,
            access_key=_read_secret(
                arguments.object_store_access_key_secret,
                label="production object-store access authority",
            ),
            secret_key=_read_secret(
                arguments.object_store_secret_key_secret,
                label="production object-store secret authority",
            ),
        )
        pipeline = build_production_event_pipeline(
            site_id=arguments.site_id,
            site=active_site,
            compiled_rules=compiled_rules,
            writer_receipt=writer_receipt,
            repository=bound_repository,
            evidence_client=object_client,
            preview_client=object_client,
            journal_path=_JOURNAL_PATH,
            preview_workspace_root=_PREVIEW_WORKSPACE,
            preview_context_factory=lambda reservation, evidence: (
                _preview_context(
                    bound_repository,
                    site_id=arguments.site_id,
                    reservation=reservation,
                    evidence=evidence,
                )
            ),
            clock=lambda: datetime.now(UTC),
        )
        telemetry_client = AuthenticatedTelemetryClient(
            base_url=arguments.control_plane_url,
            machine_token=read_machine_token(
                arguments.machine_token_file,
            ),
        )
        bindings = _load_nvidia_bindings()
        loop = bindings.glib.MainLoop()
        runtime = DeepStreamDataPlane(
            runtime_manifest=runtime_manifest,
            runtime_info=_target_runtime_info,
            binding_loader=lambda: bindings,
            fatal_callback=loop.quit,
            evidence_sink_factory=(
                pipeline.dependencies.evidence_sink_factory
            ),
            runtime_session_seed_factory=lambda: runtime_session_id,
            telemetry_publisher_factory=lambda session_id: (
                AsyncRuntimeTelemetryPublisher(
                    publisher=RuntimeTelemetryPublisher(
                        client=telemetry_client,
                        runtime_session_id=session_id,
                    ),
                    extra_metrics_provider=TargetResourceMetricsProvider(
                        spool_root=(
                            active_site.storage.retention.encoded_spool_root
                        ),
                    ),
                )
            ),
            native_probe_lease_factory=(
                pipeline.dependencies.native_source_authority
            ),
        )
        worker = pipeline.bind_observation_source(runtime)
        worker.start()
        runtime.start(active_site)
        result = _run_operational_loop(
            runtime=runtime,
            worker=worker,
            loop=loop,
            glib=bindings.glib,
        )
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            primary = exc
        else:
            primary = ProductionRuntimeError(
                "production runtime failed closed"
            )
            primary.__cause__ = exc

    cleanup: BaseException | None = None
    try:
        _shutdown_production_components(
            runtime=runtime,
            pipeline=pipeline,
            worker=worker,
            object_client=object_client,
            engine=engine,
        )
    except BaseException as exc:
        cleanup = exc

    if primary is not None and cleanup is not None:
        raise BaseExceptionGroup(
            "production runtime and shutdown failed closed",
            [primary, cleanup],
        )
    if cleanup is not None:
        raise cleanup
    if primary is not None:
        if isinstance(primary, (KeyboardInterrupt, SystemExit)):
            raise primary
        raise primary
    return result


if __name__ == "__main__":
    raise SystemExit(main())
