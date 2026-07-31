from __future__ import annotations

import inspect

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from protector.pilot.acceptance_controller_v3 import AcceptanceControllerResultV3
from protector.pilot.api.acceptance_controller import (
    create_v3_acceptance_controller_app,
)


class _CollectorBoundAuthority:
    def __init__(self) -> None:
        self.collectors: list[str] = []
        self.readiness_calls = 0

    def finalize_collector(self, collector_id: str) -> dict[str, object]:
        self.collectors.append(collector_id)
        return {
            "schema_version": "acceptance-controller-result.v3",
            "collector_id": collector_id,
            "state": "ATTESTED",
            "snapshot_sha256": "1" * 64,
            "evaluation_sha256": "2" * 64,
            "final_decision_sha256": "3" * 64,
            "proof_sha256": "4" * 64,
            "accepted": False,
            "pass_attestation": None,
        }

    def readiness_probe(self) -> None:
        self.readiness_calls += 1


def test_production_v3_surface_accepts_only_collector_bound_finalization() -> None:
    authority = _CollectorBoundAuthority()
    app = create_v3_acceptance_controller_app(
        authority=authority,
        controller_token="controller-token-1234",
    )
    client = TestClient(app)
    headers = {"Authorization": "Bearer controller-token-1234"}

    response = client.post(
        "/api/internal/acceptance/v3/collectors/collector-01/finalize",
        headers=headers,
    )
    assert response.status_code == 200
    assert authority.collectors == ["collector-01"]
    assert response.json()["collector_id"] == "collector-01"

    for legacy in (
        "/api/internal/acceptance/start",
        "/api/internal/acceptance/sample",
        "/api/internal/acceptance/fault/prepare",
        "/api/internal/acceptance/fault/ack",
        "/api/internal/acceptance/finalize",
        "/api/internal/acceptance/proof",
    ):
        assert client.post(legacy, headers=headers, json={}).status_code == 404

    signature = inspect.signature(authority.finalize_collector)
    assert tuple(signature.parameters) == ("collector_id",)


def test_controller_result_acceptance_requires_a_bound_pass_attestation() -> None:
    with pytest.raises(ValidationError, match="pass attestation|accepted"):
        AcceptanceControllerResultV3(
            schema_version="acceptance-controller-result.v3",
            collector_id="collector-01",
            state="ATTESTED",
            snapshot_sha256="1" * 64,
            evaluation_sha256="2" * 64,
            final_decision_sha256="3" * 64,
            proof_sha256="4" * 64,
            accepted=True,
            pass_attestation=None,
        )


def test_v3_restart_guard_fails_before_finalize_or_readiness_authority() -> None:
    authority = _CollectorBoundAuthority()

    def blocked() -> None:
        raise RuntimeError("continuation authority is incomplete")

    app = create_v3_acceptance_controller_app(
        authority=authority,
        controller_token="controller-token-1234",
        authorization_guard=blocked,
    )
    client = TestClient(app)
    headers = {"Authorization": "Bearer controller-token-1234"}

    finalized = client.post(
        "/api/internal/acceptance/v3/collectors/collector-01/finalize",
        headers=headers,
    )
    ready = client.get("/ready", headers=headers)

    assert finalized.status_code == 409
    assert ready.status_code == 503
    assert authority.collectors == []
    assert authority.readiness_calls == 0
