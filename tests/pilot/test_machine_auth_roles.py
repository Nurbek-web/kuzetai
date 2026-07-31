from __future__ import annotations

import base64
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient

from protector.pilot.api.app import create_app
from protector.pilot.metrics import (
    HealthProbeSnapshot,
    PilotHealthService,
    PilotMetrics,
    PilotTelemetryState,
)
from protector.pilot.storage.db import create_engine, create_session_factory
from protector.pilot.storage.models import Base
from protector.pilot.storage.repositories import PilotRepository

NOW = datetime(2026, 7, 31, 9, 0, tzinfo=UTC)
CAMERAS = tuple(f"cam-{index:02d}" for index in range(1, 21))
RUNTIME_TOKEN = "runtime-write-token-at-least-16"
NOTIFICATION_TOKEN = "notification-telemetry-token-at-least-16"
MONITORING_TOKEN = "monitoring-read-token-at-least-16"


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _runtime_payload() -> dict[str, object]:
    return {
        "publisher": "runtime",
        "runtime_session_id": "runtime-auth-test",
        "publisher_generation": 1,
        "sequence": 1,
        "observed_at": NOW.isoformat(),
        "components": [
            {"name": "analytics", "state": "healthy"},
            {"name": "evidence", "state": "healthy"},
        ],
        "health": [
            {
                "camera_id": camera_id,
                "runtime_session_id": "runtime-auth-test",
                "observed_at": NOW.isoformat(),
                "state": "online",
                "last_frame_at": NOW.isoformat(),
                "reconnect_count": 0,
                "dropped_samples": 0,
            }
            for camera_id in CAMERAS
        ],
    }


def _notification_payload() -> dict[str, object]:
    return {
        "publisher": "notifications",
        "runtime_session_id": "notification-auth-test",
        "publisher_generation": 1,
        "sequence": 1,
        "observed_at": NOW.isoformat(),
        "components": [{"name": "notifications", "state": "healthy"}],
        "notification_results": [{"result": "attempted", "total": 1}],
    }


def test_scoped_machine_credentials_are_route_and_publisher_isolated() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        engine = create_engine(f"sqlite+pysqlite:///{root / 'roles.db'}")
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
        app = create_app(
            repository=repository,
            session_secret="session-secret-at-least-32-characters",
            totp_encryption_key=base64.urlsafe_b64encode(b"t" * 32).decode(),
            runtime_machine_token=RUNTIME_TOKEN,
            notification_machine_token=NOTIFICATION_TOKEN,
            monitoring_machine_token=MONITORING_TOKEN,
            pilot_site_id="site-1",
            metrics=metrics,
            telemetry=telemetry,
            health=PilotHealthService(
                site_id="site-1",
                camera_ids=CAMERAS,
                probe=lambda: HealthProbeSnapshot(
                    site_id="site-1",
                    camera_states={camera_id: "online" for camera_id in CAMERAS},
                    control_plane="healthy",
                    database="healthy",
                    **telemetry.component_states(),
                ),
            ),
            runtime_lock_path=root / "roles.lock",
        )
        client = TestClient(app, base_url="https://testserver")

        assert client.get(
            "/internal/metrics", headers=_headers(MONITORING_TOKEN)
        ).status_code == 200
        assert client.get(
            "/internal/metrics", headers=_headers(RUNTIME_TOKEN)
        ).status_code == 401
        assert client.get(
            "/internal/health/live", headers=_headers(NOTIFICATION_TOKEN)
        ).status_code == 401

        runtime = client.post(
            "/api/internal/telemetry",
            headers=_headers(RUNTIME_TOKEN),
            json=_runtime_payload(),
        )
        assert runtime.status_code == 202
        assert client.post(
            "/api/internal/telemetry",
            headers=_headers(NOTIFICATION_TOKEN),
            json=_runtime_payload(),
        ).status_code == 401
        assert client.post(
            "/api/internal/telemetry",
            headers=_headers(MONITORING_TOKEN),
            json=_runtime_payload(),
        ).status_code == 401

        notification = client.post(
            "/api/internal/telemetry",
            headers=_headers(NOTIFICATION_TOKEN),
            json=_notification_payload(),
        )
        assert notification.status_code == 202
        assert client.post(
            "/api/internal/telemetry",
            headers=_headers(RUNTIME_TOKEN),
            json=_notification_payload(),
        ).status_code == 401
        assert client.post(
            "/api/internal/health",
            headers=_headers(MONITORING_TOKEN),
            json={
                "camera_id": "cam-01",
                "runtime_session_id": "runtime-auth-test",
                "observed_at": NOW.isoformat(),
                "state": "online",
                "last_frame_at": NOW.isoformat(),
                "reconnect_count": 0,
                "dropped_samples": 0,
            },
        ).status_code == 401
