from __future__ import annotations

import base64
import math
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

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
)
from protector.pilot.storage.db import create_engine, create_session_factory
from protector.pilot.storage.models import Base, CameraHealthSampleModel
from protector.pilot.storage.repositories import PilotRepository

NOW = datetime(2026, 7, 29, 9, 0, tzinfo=UTC)
CAMERAS = tuple(f"cam-{index:02d}" for index in range(1, 21))
MACHINE_TOKEN = "metrics-machine-token-at-least-16"


def _metrics() -> PilotMetrics:
    return PilotMetrics(
        site_id="site-1",
        camera_ids=CAMERAS,
        model_artifact_ids=("person-v1", "weapon-v2"),
    )


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
