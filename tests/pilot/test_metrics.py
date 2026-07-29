from __future__ import annotations

import base64
import math
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from protector.pilot.api.app import create_app
from protector.pilot.api.production import (
    build_evidence_link_signer,
    read_component_state,
    refresh_camera_metrics,
    source_health_state,
)
from protector.pilot.metrics import (
    HealthProbeSnapshot,
    PilotHealthService,
    PilotMetrics,
    PilotTelemetryState,
)
from protector.pilot.runtime.supervisor import CameraHealth
from protector.pilot.storage.db import create_engine, create_session_factory
from protector.pilot.storage.models import Base, CameraHealthSampleModel
from protector.pilot.storage.repositories import PilotRepository
from protector.pilot.telemetry import (
    AsyncRuntimeTelemetryPublisher,
    NotificationTelemetryPublisher,
    RuntimeTelemetryPublisher,
    TargetResourceMetricsProvider,
)

NOW = datetime(2026, 7, 29, 9, 0, tzinfo=UTC)
CAMERAS = tuple(f"cam-{index:02d}" for index in range(1, 21))
MACHINE_TOKEN = "metrics-machine-token-at-least-16"


def _metrics() -> PilotMetrics:
    return PilotMetrics(
        site_id="site-1",
        camera_ids=CAMERAS,
        model_artifact_ids=("person-v1", "weapon-v2"),
    )


def _telemetry_app(
    tmp_path: Path,
) -> tuple[TestClient, PilotMetrics]:
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'telemetry.db'}")
    Base.metadata.create_all(engine)
    repository = PilotRepository(create_session_factory(engine))
    repository.add_site(site_id="site-1", name="Pilot")
    for camera_id in CAMERAS:
        repository.add_camera(
            camera_id=camera_id,
            site_id="site-1",
            name=camera_id,
            source_reference="secret://source",
            codec="h264",
        )
    metrics = PilotMetrics(
        site_id="site-1",
        camera_ids=CAMERAS,
        model_artifact_ids=("person-v1",),
    )
    telemetry = PilotTelemetryState(
        site_id="site-1",
        stale_after_seconds=30,
        clock=lambda: NOW,
    )

    def probe() -> HealthProbeSnapshot:
        return HealthProbeSnapshot(
            site_id="site-1",
            camera_states={camera_id: "online" for camera_id in CAMERAS},
            control_plane="healthy",
            database="healthy",
            **telemetry.component_states(),
        )

    app = create_app(
        repository=repository,
        session_secret="telemetry-session-secret-at-least-32-characters",
        totp_encryption_key=base64.urlsafe_b64encode(b"t" * 32).decode(),
        machine_token=MACHINE_TOKEN,
        pilot_site_id="site-1",
        metrics=metrics,
        telemetry=telemetry,
        health=PilotHealthService(
            site_id="site-1",
            camera_ids=CAMERAS,
            probe=probe,
        ),
        runtime_lock_path=tmp_path / "telemetry-app.lock",
    )
    return TestClient(app, base_url="https://testserver"), metrics


def _snapshot(**overrides: object) -> HealthProbeSnapshot:
    values: dict[str, object] = {
        "site_id": "site-1",
        "camera_states": {camera_id: "online" for camera_id in CAMERAS},
        "control_plane": "healthy",
        "database": "healthy",
        "analytics": "healthy",
        "evidence": "healthy",
        "notifications": "healthy",
    }
    values.update(overrides)
    return HealthProbeSnapshot(**values)  # type: ignore[arg-type]


def _health_envelope() -> list[dict[str, object]]:
    return [
        {
            "camera_id": camera_id,
            "runtime_session_id": "runtime-a",
            "observed_at": NOW.isoformat(),
            "state": "online",
            "last_frame_at": NOW.isoformat(),
            "reconnect_count": 0,
            "dropped_samples": 0,
            "degraded_reason": None,
        }
        for camera_id in CAMERAS
    ]


def test_metrics_registry_is_isolated_low_cardinality_and_snapshot_safe() -> None:
    first = _metrics()
    second = _metrics()

    first.update_camera(
        "cam-01",
        available=True,
        last_frame_age_seconds=0.25,
        reconnects_total=3,
    )
    first.update_camera(
        "cam-01",
        available=False,
        last_frame_age_seconds=1.5,
        reconnects_total=5,
    )
    first.update_samples(
        "cam-01",
        module="person",
        scheduled_total=10,
        processed_total=8,
        dropped_total=2,
    )
    first.update_samples(
        "cam-01",
        module="person",
        scheduled_total=10,
        processed_total=8,
        dropped_total=2,
    )
    first.set_queue_age(queue="analytics", age_seconds=0.4)
    first.observe_model_latency(
        module="person",
        model_artifact_id="person-v1",
        latency_seconds=0.02,
    )
    first.record_candidate(module="person")
    first.record_evidence(result="ready", latency_seconds=0.8)
    first.record_evidence(result="failed")
    first.set_gpu(utilization_percent=72.0, vram_used_bytes=10, vram_capacity_bytes=24)
    first.set_disk(used_bytes=100, capacity_bytes=1_000)
    first.record_notification(result="delivered")
    first.record_notification(result="dead_letter")

    payload = first.render().decode()
    assert 'kuzet_camera_available{camera_id="cam-01",site_id="site-1"} 0.0' in payload
    assert (
        'kuzet_camera_reconnects_total{camera_id="cam-01",site_id="site-1"} 5.0'
        in payload
    )
    assert (
        'kuzet_analysis_samples_total{camera_id="cam-01",module="person",'
        'result="scheduled",site_id="site-1"} 10.0'
    ) in payload
    assert "event_id=" not in payload
    assert "sample_id=" not in payload
    assert "attempt_id=" not in payload
    assert "object_key=" not in payload
    assert "rtsp://" not in payload
    assert second.render() != first.render()


@pytest.mark.parametrize("bad_value", (-1, math.nan, math.inf, -math.inf))
def test_metrics_reject_invalid_values_unknown_dimensions_and_counter_regression(
    bad_value: float,
) -> None:
    metrics = _metrics()

    with pytest.raises(ValueError):
        metrics.set_queue_age(queue="analytics", age_seconds=bad_value)
    with pytest.raises(ValueError):
        metrics.update_camera(
            "foreign-camera",
            available=True,
            last_frame_age_seconds=0,
            reconnects_total=0,
        )
    with pytest.raises(ValueError):
        metrics.observe_model_latency(
            module="person",
            model_artifact_id="unconfigured",
            latency_seconds=0.1,
        )
    with pytest.raises(ValueError):
        metrics.update_camera(
            "cam-01",
            available=True,
            last_frame_age_seconds=0,
            reconnects_total=1.5,  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError, match="processed and dropped"):
        metrics.update_samples(
            "cam-01",
            module="restricted_zone",
            scheduled_total=2,
            processed_total=2,
            dropped_total=1,
        )

    metrics.update_samples(
        "cam-01",
        module="person",
        scheduled_total=2,
        processed_total=2,
        dropped_total=0,
    )
    with pytest.raises(ValueError, match="regressed"):
        metrics.update_samples(
            "cam-01",
            module="person",
            scheduled_total=1,
            processed_total=1,
            dropped_total=0,
        )

    metrics.record_candidate(module="weapon")
    metrics.record_candidate(module="line_crossing")
    metrics.record_candidate(module="fight")
    metrics.record_candidate(module="xclip")
    with pytest.raises(ValueError):
        metrics.set_gpu(
            utilization_percent=1,
            vram_used_bytes=1.5,  # type: ignore[arg-type]
            vram_capacity_bytes=24,
        )
    with pytest.raises(ValueError):
        metrics.set_disk(used_bytes=True, capacity_bytes=100)  # type: ignore[arg-type]


def test_concurrent_identical_counter_snapshots_are_counted_once() -> None:
    metrics = _metrics()

    def publish(_: int) -> None:
        metrics.update_camera(
            "cam-01",
            available=True,
            last_frame_age_seconds=0,
            reconnects_total=7,
        )

    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(publish, range(128)))

    assert (
        'kuzet_camera_reconnects_total{camera_id="cam-01",site_id="site-1"} 7.0'
        in metrics.render().decode()
    )


def test_runtime_session_restart_resets_snapshots_without_breaking_scrape() -> None:
    metrics = _metrics()
    for runtime_session_id, reconnects_total in (
        ("runtime-a", 7),
        ("runtime-b", 0),
        ("runtime-b", 2),
    ):
        metrics.update_camera(
            "cam-01",
            available=True,
            last_frame_age_seconds=0.1,
            reconnects_total=reconnects_total,
            runtime_session_id=runtime_session_id,
        )

    assert (
        'kuzet_camera_reconnects_total{camera_id="cam-01",site_id="site-1"} 9.0'
        in metrics.render().decode()
    )


def test_runtime_publisher_emits_twenty_health_samples_and_one_bounded_envelope() -> None:
    requests: list[tuple[str, dict[str, object]]] = []

    class Client:
        def post(self, path: str, payload: dict[str, object]) -> None:
            requests.append((path, payload))

    health = [
        CameraHealth(
            camera_id=camera_id,
            state="online",
            stream_epoch=uuid4(),
            last_frame_at=NOW - timedelta(milliseconds=index),
            last_frame_age_seconds=index / 1_000,
            reconnect_count=index,
            reconnect_backoff_seconds=0,
            next_reconnect_in_seconds=None,
            source_time_skew_seconds=0.01,
            scheduled_samples=10,
            dropped_samples=1,
            queue_age_seconds=0.2,
            degraded_reason=None,
            last_monotonic_seq=10,
            tracker_generation=0,
        )
        for index, camera_id in enumerate(CAMERAS)
    ]
    publisher = RuntimeTelemetryPublisher(
        client=Client(),  # type: ignore[arg-type]
        runtime_session_id="runtime-a",
        clock=lambda: NOW,
    )

    publisher.publish(
        health,
        analytics_state="healthy",
        evidence_state="healthy",
    )

    assert len(requests) == 1
    telemetry = [payload for path, payload in requests if path.endswith("/telemetry")]
    assert len(telemetry) == 1
    assert telemetry[0]["publisher"] == "runtime"
    assert telemetry[0]["sequence"] == 1
    assert len(telemetry[0]["samples"]) == 20  # type: ignore[arg-type]
    assert len(telemetry[0]["health"]) == 20  # type: ignore[arg-type]
    assert "source_reference" not in str(requests)


def test_notification_publisher_owns_only_cumulative_delivery_results() -> None:
    requests: list[dict[str, object]] = []

    class Client:
        def post(self, path: str, payload: dict[str, object]) -> None:
            assert path == "/api/internal/telemetry"
            requests.append(payload)

    publisher = NotificationTelemetryPublisher(
        client=Client(),  # type: ignore[arg-type]
        worker_session_id="notifications-a",
        clock=lambda: NOW,
    )
    publisher.publish(
        state="healthy",
        attempted=2,
        delivered=1,
        failed=1,
        dead_letter=0,
    )
    publisher.publish(
        state="degraded",
        attempted=3,
        delivered=2,
        failed=1,
        dead_letter=0,
    )

    assert [request["sequence"] for request in requests] == [1, 2]
    assert requests[0]["components"] == [
        {"name": "notifications", "state": "healthy"}
    ]
    assert "samples" not in requests[0]
    assert requests[1]["notification_results"] == [
        {"result": "attempted", "total": 3},
        {"result": "delivered", "total": 2},
        {"result": "failed", "total": 1},
        {"result": "dead_letter", "total": 0},
    ]
    with pytest.raises(ValueError, match="cumulative"):
        publisher.publish(
            state="healthy",
            attempted=2,
            delivered=2,
            failed=1,
            dead_letter=0,
        )


def test_runtime_telemetry_background_queue_is_nonblocking_drop_old_and_finitely_closed() -> None:
    began = threading.Event()
    release = threading.Event()
    published: list[int] = []

    class Publisher:
        def publish(
            self,
            health: list[int],
            *,
            analytics_state: str,
            evidence_state: str,
            extra_runtime_metrics: object | None = None,
        ) -> None:
            del analytics_state, evidence_state, extra_runtime_metrics
            began.set()
            release.wait(timeout=2)
            published.append(health[0])

    background = AsyncRuntimeTelemetryPublisher(
        publisher=Publisher(),  # type: ignore[arg-type]
        shutdown_timeout_seconds=0.5,
    )
    background.enqueue([1], analytics_state="healthy", evidence_state="healthy")  # type: ignore[list-item]
    assert began.wait(timeout=1)
    started = time.monotonic()
    background.enqueue([2], analytics_state="healthy", evidence_state="healthy")  # type: ignore[list-item]
    background.enqueue([3], analytics_state="healthy", evidence_state="healthy")  # type: ignore[list-item]
    assert time.monotonic() - started < 0.1
    release.set()
    deadline = time.monotonic() + 1
    while len(published) < 2 and time.monotonic() < deadline:
        time.sleep(0.01)
    background.close()

    assert published == [1, 3]
    assert background.worker_alive is False


def test_target_resource_probe_reports_measured_gpu_vram_and_spool_disk(
    tmp_path: Path,
) -> None:
    class Result:
        stdout = "41, 1024, 8192\n"

    provider = TargetResourceMetricsProvider(
        spool_root=tmp_path,
        command_runner=lambda *_args, **_kwargs: Result(),
        disk_usage=lambda _: (10_000, 2_000, 8_000),
    )

    assert provider() == {
        "gpu": {
            "utilization_percent": 41.0,
            "vram_used_bytes": 1024 * 1024 * 1024,
            "vram_capacity_bytes": 8192 * 1024 * 1024,
        },
        "disk": {"used_bytes": 2_000, "capacity_bytes": 10_000},
    }


def test_authenticated_runtime_and_worker_telemetry_is_scraped_and_drives_readiness(
    tmp_path: Path,
) -> None:
    client, _ = _telemetry_app(tmp_path)
    headers = {"Authorization": f"Bearer {MACHINE_TOKEN}"}
    runtime = client.post(
        "/api/internal/telemetry",
        headers=headers,
        json={
            "publisher": "runtime",
            "runtime_session_id": "runtime-a",
            "sequence": 1,
            "observed_at": NOW.isoformat(),
            "components": [
                {"name": "analytics", "state": "healthy"},
                {"name": "evidence", "state": "healthy"},
            ],
            "health": _health_envelope(),
            "samples": [
                {
                    "camera_id": "cam-01",
                    "module": "person",
                    "scheduled_total": 4,
                    "processed_total": 3,
                    "dropped_total": 1,
                }
            ],
            "queues": [{"name": "analytics", "age_seconds": 0.2}],
            "model_latencies": [
                {
                    "module": "person",
                    "model_artifact_id": "person-v1",
                    "latency_seconds": 0.03,
                }
            ],
            "candidate_totals": [{"module": "person", "total": 2}],
            "evidence_results": [{"result": "ready", "total": 1}],
            "evidence_latencies_seconds": [0.4],
            "gpu": {
                "utilization_percent": 41.0,
                "vram_used_bytes": 1_000,
                "vram_capacity_bytes": 4_000,
            },
            "disk": {"used_bytes": 2_000, "capacity_bytes": 10_000},
        },
    )
    notifications = client.post(
        "/api/internal/telemetry",
        headers=headers,
        json={
            "publisher": "notifications",
            "runtime_session_id": "worker-a",
            "sequence": 1,
            "observed_at": NOW.isoformat(),
            "components": [{"name": "notifications", "state": "healthy"}],
            "notification_results": [
                {"result": "attempted", "total": 1},
                {"result": "delivered", "total": 1},
            ],
        },
    )

    assert runtime.status_code == 202
    assert notifications.status_code == 202
    scraped = client.get("/internal/metrics", headers=headers)
    ready = client.get("/internal/health/ready", headers=headers)
    assert scraped.status_code == 200
    assert (
        'kuzet_analysis_samples_total{camera_id="cam-01",module="person",'
        'result="scheduled",site_id="site-1"} 4.0'
    ) in scraped.text
    assert (
        'kuzet_notification_results_total{result="delivered",site_id="site-1"} 1.0'
        in scraped.text
    )
    assert ready.status_code == 200
    assert ready.json()["status"] == "ready"
    assert (
        'kuzet_evidence_results_total{result="ready",site_id="site-1"} 1.0'
        in scraped.text
    )


def test_telemetry_rejects_cross_publisher_fields_and_duplicate_finite_keys(
    tmp_path: Path,
) -> None:
    client, metrics = _telemetry_app(tmp_path)
    headers = {"Authorization": f"Bearer {MACHINE_TOKEN}"}
    runtime_crosses_boundary = client.post(
        "/api/internal/telemetry",
        headers=headers,
        json={
            "publisher": "runtime",
            "runtime_session_id": "runtime-a",
            "sequence": 1,
            "observed_at": NOW.isoformat(),
            "components": [
                {"name": "analytics", "state": "healthy"},
                {"name": "evidence", "state": "healthy"},
            ],
            "health": _health_envelope(),
            "notification_results": [{"result": "delivered", "total": 1}],
        },
    )
    worker_crosses_boundary = client.post(
        "/api/internal/telemetry",
        headers=headers,
        json={
            "publisher": "notifications",
            "runtime_session_id": "worker-a",
            "sequence": 1,
            "observed_at": NOW.isoformat(),
            "components": [{"name": "notifications", "state": "healthy"}],
            "candidate_totals": [
                {"module": "person", "total": 1},
                {"module": "person", "total": 2},
            ],
        },
    )

    assert runtime_crosses_boundary.status_code == 422
    assert worker_crosses_boundary.status_code == 422
    rendered = metrics.render().decode()
    assert 'kuzet_notification_results_total{result="delivered"' not in rendered
    assert 'kuzet_candidates_total{module="person"' not in rendered


def test_telemetry_prevalidates_full_envelope_and_binds_duplicate_sequence_to_body(
    tmp_path: Path,
) -> None:
    client, metrics = _telemetry_app(tmp_path)
    headers = {"Authorization": f"Bearer {MACHINE_TOKEN}"}
    base = {
        "publisher": "runtime",
        "runtime_session_id": "runtime-a",
        "sequence": 1,
        "observed_at": NOW.isoformat(),
        "components": [
            {"name": "analytics", "state": "healthy"},
            {"name": "evidence", "state": "healthy"},
        ],
        "health": _health_envelope(),
        "samples": [
            {
                "camera_id": "cam-01",
                "module": "person",
                "scheduled_total": 4,
                "processed_total": 4,
                "dropped_total": 0,
            }
        ],
    }
    accepted = client.post("/api/internal/telemetry", headers=headers, json=base)
    changed_replay = client.post(
        "/api/internal/telemetry",
        headers=headers,
        json={
            **base,
            "samples": [
                {
                    "camera_id": "cam-01",
                    "module": "person",
                    "scheduled_total": 5,
                    "processed_total": 5,
                    "dropped_total": 0,
                }
            ],
        },
    )
    late_invalid = client.post(
        "/api/internal/telemetry",
        headers=headers,
        json={
            **base,
            "sequence": 2,
            "samples": [
                {
                    "camera_id": "cam-01",
                    "module": "person",
                    "scheduled_total": 5,
                    "processed_total": 5,
                    "dropped_total": 0,
                }
            ],
            "model_latencies": [
                {
                    "module": "person",
                    "model_artifact_id": "unknown-artifact",
                    "latency_seconds": 0.1,
                }
            ],
        },
    )

    assert accepted.status_code == 202
    assert changed_replay.status_code == 422
    assert late_invalid.status_code == 422
    rendered = metrics.render().decode()
    assert (
        'kuzet_analysis_samples_total{camera_id="cam-01",module="person",'
        'result="scheduled",site_id="site-1"} 4.0'
    ) in rendered


def test_health_distinguishes_process_database_sources_analytics_storage_and_notifications() -> None:
    healthy = PilotHealthService(
        site_id="site-1",
        camera_ids=CAMERAS,
        probe=lambda: _snapshot(),
    )
    assert healthy.liveness() == {"status": "alive", "control_plane": "healthy"}
    assert healthy.readiness()["status"] == "ready"

    degraded = PilotHealthService(
        site_id="site-1",
        camera_ids=CAMERAS,
        probe=lambda: _snapshot(
            database="failed",
            camera_states={**_snapshot().camera_states, "cam-04": "offline"},
            analytics="degraded",
            evidence="failed",
            notifications="degraded",
        ),
    ).readiness()

    assert degraded == {
        "status": "not_ready",
        "site": "configured",
        "camera_count": 20,
        "components": {
            "control_plane": "healthy",
            "database": "failed",
            "sources": "degraded",
            "analytics": "degraded",
            "evidence": "failed",
            "notifications": "degraded",
        },
    }
    assert "cam-04" not in str(degraded)


def test_readiness_fails_closed_for_wrong_site_or_not_exactly_twenty_cameras() -> None:
    service = PilotHealthService(
        site_id="site-1",
        camera_ids=CAMERAS,
        probe=lambda: _snapshot(site_id="foreign-site"),
    )
    assert service.readiness()["status"] == "not_ready"
    assert service.readiness()["site"] == "mismatch"

    with pytest.raises(ValueError, match="exactly 20"):
        PilotHealthService(
            site_id="site-1",
            camera_ids=CAMERAS[:-1],
            probe=lambda: _snapshot(),
        )


def test_internal_metrics_and_health_routes_require_machine_auth(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'metrics.db'}")
    Base.metadata.create_all(engine)
    repository = PilotRepository(create_session_factory(engine))
    repository.add_site(site_id="site-1", name="Pilot")
    for camera_id in CAMERAS:
        repository.add_camera(
            camera_id=camera_id,
            site_id="site-1",
            name=camera_id,
            source_reference="secret://source",
            codec="h264",
            state="online",
        )
    with repository.session_factory.begin() as session:
        session.add(
            CameraHealthSampleModel(
                camera_id="cam-01",
                observed_at=NOW,
                state="online",
                last_frame_at=NOW - timedelta(seconds=1),
                reconnect_count=3,
                dropped_samples=0,
            )
        )
    database_metrics = _metrics()
    refresh_camera_metrics(
        metrics=database_metrics,
        session_factory=repository.session_factory,
        site_id="site-1",
        camera_ids=CAMERAS,
        stale_after_seconds=5,
        now=NOW,
    )
    database_payload = database_metrics.render().decode()
    assert 'kuzet_camera_available{camera_id="cam-01",site_id="site-1"} 1.0' in database_payload
    assert 'kuzet_camera_available{camera_id="cam-02",site_id="site-1"} 0.0' in database_payload

    pilot_metrics = _metrics()

    def refresh_metrics() -> None:
        pilot_metrics.update_camera(
            "cam-01",
            available=True,
            last_frame_age_seconds=0.5,
            reconnects_total=4,
        )

    app = create_app(
        repository=repository,
        session_secret="session-secret-at-least-32-characters",
        totp_encryption_key=base64.urlsafe_b64encode(b"m" * 32).decode(),
        machine_token=MACHINE_TOKEN,
        pilot_site_id="site-1",
        metrics=pilot_metrics,
        metrics_refresh=refresh_metrics,
        health=PilotHealthService(
            site_id="site-1",
            camera_ids=CAMERAS,
            probe=lambda: _snapshot(),
        ),
    )
    client = TestClient(app, base_url="https://testserver")

    assert client.get("/internal/metrics").status_code == 401
    assert client.get("/internal/health").status_code == 401
    headers = {"Authorization": f"Bearer {MACHINE_TOKEN}"}
    metrics = client.get("/internal/metrics", headers=headers)
    health = client.get("/internal/health", headers=headers)
    ready = client.get("/internal/health/ready", headers=headers)
    live = client.get("/internal/health/live", headers=headers)

    assert metrics.status_code == 200
    repeated_metrics = client.get("/internal/metrics", headers=headers)
    assert repeated_metrics.status_code == 200
    assert (
        'kuzet_camera_reconnects_total{camera_id="cam-01",site_id="site-1"} 4.0'
        in repeated_metrics.text
    )
    assert metrics.headers["content-type"].startswith("text/plain")
    assert health.json()["components"]["sources"] == "healthy"
    assert ready.json()["status"] == "ready"
    assert live.json() == {"status": "alive", "control_plane": "healthy"}
    assert "secret://source" not in health.text

    failed_app = create_app(
        repository=repository,
        session_secret="another-session-secret-at-least-32-characters",
        totp_encryption_key=base64.urlsafe_b64encode(b"n" * 32).decode(),
        machine_token=MACHINE_TOKEN,
        pilot_site_id="site-1",
        metrics=_metrics(),
        health=PilotHealthService(
            site_id="site-1",
            camera_ids=CAMERAS,
            probe=lambda: _snapshot(control_plane="failed", database="failed"),
        ),
        runtime_lock_path=tmp_path / "failed-app.lock",
    )
    failed_client = TestClient(failed_app, base_url="https://testserver")
    assert failed_client.get("/internal/health/live", headers=headers).status_code == 503
    assert failed_client.get("/internal/health/ready", headers=headers).status_code == 503
    assert failed_client.get("/internal/health", headers=headers).status_code == 200


def test_production_component_health_files_fail_closed_and_refuse_symlinks(
    tmp_path: Path,
) -> None:
    state = tmp_path / "analytics"
    assert read_component_state(state) == "failed"
    state.write_text("healthy\n")
    assert read_component_state(state) == "healthy"
    state.write_text("provider body with rtsp://secret\n")
    assert read_component_state(state) == "failed"
    state.unlink()
    target = tmp_path / "target"
    target.write_text("healthy\n")
    state.symlink_to(target)
    assert read_component_state(state) == "failed"


def test_production_signer_decodes_secret_and_uses_explicit_bounded_ttl() -> None:
    encoded = base64.urlsafe_b64encode(b"s" * 32).decode()
    signer = build_evidence_link_signer(
        encoded_secret=encoded,
        application_origin="https://pilot.example.kz",
        ttl_seconds=300,
    )
    assert "pilot.example.kz" in repr(signer)
    with pytest.raises(ValueError):
        build_evidence_link_signer(
            encoded_secret=encoded,
            application_origin="https://pilot.example.kz",
            ttl_seconds=86_401,
        )


def test_production_source_health_requires_fresh_latest_frame_and_sample() -> None:
    assert (
        source_health_state(
            camera_state="online",
            sample_state="online",
            last_frame_at=NOW,
            observed_at=NOW,
            now=NOW,
            stale_after_seconds=5,
        )
        == "online"
    )
    assert (
        source_health_state(
            camera_state="online",
            sample_state="online",
            last_frame_at=NOW - timedelta(seconds=6),
            observed_at=NOW,
            now=NOW,
            stale_after_seconds=5,
        )
        == "degraded"
    )
    assert (
        source_health_state(
            camera_state="online",
            sample_state=None,
            last_frame_at=None,
            observed_at=None,
            now=NOW,
            stale_after_seconds=5,
        )
        == "offline"
    )
