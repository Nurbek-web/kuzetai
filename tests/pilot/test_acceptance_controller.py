import hashlib
from pathlib import Path
from types import SimpleNamespace

import yaml
from fastapi.testclient import TestClient

from protector.pilot.api.acceptance_controller import (
    create_acceptance_controller_app,
)


class _Authority:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def sample(self, payload: dict[str, object]) -> dict[str, object]:
        self.calls.append(("sample", payload))
        return {
            "schema_version": "acceptance-collector-sample-response.v2",
            **{
                field: payload[field]
                for field in (
                    "collector_id",
                    "site_id",
                    "manifest_sha256",
                    "gate",
                    "launch_attestation_sha256",
                    "execution_binding_sha256",
                    "fault_schedule_sha256",
                    "trust_binding",
                )
                if field in payload
            },
            "observed_records": 0,
        }

    def finalize(self, payload: dict[str, object]) -> dict[str, object]:
        self.calls.append(("finalize", payload))
        raise RuntimeError("fixture has no sealed final evidence")


def _binding(*, collector_id: str = "collector-1") -> dict[str, object]:
    return {
        "collector_id": collector_id,
        "site_id": "school-01",
        "manifest_sha256": "1" * 64,
        "gate": "8h",
        "launch_attestation_sha256": "2" * 64,
        "execution_binding_sha256": "3" * 64,
        "fault_schedule_sha256": "4" * 64,
    }


def _sample_payload() -> dict[str, object]:
    return {
        "schema_version": "acceptance-collector-sample.v2",
        **_binding(),
        "process_healthy": True,
        "scheduled_monotonic_offset_seconds": 0.0,
    }


def _finalize_payload(*, padding: int) -> dict[str, object]:
    return {
        "schema_version": "acceptance-collector-finalize.v2",
        **_binding(),
        "candidate": {"padding": "x" * padding},
    }


def _proof_payload(*, collector_id: str) -> dict[str, object]:
    return {
        "schema_version": "acceptance-proof-request.v2",
        **_binding(collector_id=collector_id),
    }


def test_acceptance_controller_is_dedicated_and_authenticated(
    tmp_path: Path,
) -> None:
    authority = _Authority()
    app = create_acceptance_controller_app(
        authority=authority,
        controller_token="controller-token-is-separate",
        runtime_lock_path=tmp_path / "controller.lock",
    )
    with TestClient(app) as client:
        assert client.get("/live").status_code == 401
        response = client.post(
            "/api/internal/acceptance/sample",
            headers={"Authorization": "Bearer controller-token-is-separate"},
            json=_sample_payload(),
        )
    assert response.status_code == 200
    assert response.json()["schema_version"] == (
        "acceptance-collector-sample-response.v2"
    )
    assert authority.calls == [
        (
            "sample",
            {
                **_sample_payload(),
                "trust_binding": None,
                "observation": None,
            },
        )
    ]


def test_acceptance_controller_allows_only_bounded_large_finalize_bodies(
    tmp_path: Path,
) -> None:
    authority = _Authority()
    app = create_acceptance_controller_app(
        authority=authority,
        controller_token="controller-token-is-separate",
        runtime_lock_path=tmp_path / "controller-limit.lock",
        max_request_body_bytes=1024,
        max_final_request_body_bytes=4096,
    )
    headers = {"Authorization": "Bearer controller-token-is-separate"}
    payload = _finalize_payload(padding=1800)
    with TestClient(app) as client:
        assert (
            client.post(
                "/api/internal/acceptance/sample",
                headers=headers,
                json=payload,
            ).status_code
            == 413
        )
        assert (
            client.post(
                "/api/internal/acceptance/finalize",
                headers=headers,
                json=payload,
            ).status_code
            == 409
        )
        assert (
            client.post(
                "/api/internal/acceptance/finalize",
                headers=headers,
                json=_finalize_payload(padding=4096),
            ).status_code
            == 413
        )


def test_acceptance_controller_streams_only_authenticated_sealed_proof(
    tmp_path: Path,
) -> None:
    proof_payload = b'{"schema_version":"proof-header"}\n{"schema_version":"proof-trailer"}\n'

    class ProofAuthority(_Authority):
        def proof_metadata(self, payload: dict[str, object]):
            self.calls.append(("proof_metadata", payload))
            if payload.get("collector_id") == "unsealed":
                raise RuntimeError("proof is not sealed")
            return (
                SimpleNamespace(
                    journal_proof_bytes=len(proof_payload),
                    journal_proof_sha256=__import__("hashlib").sha256(proof_payload).hexdigest(),
                    journal_proof_lines=2,
                ),
                iter((proof_payload[:17], proof_payload[17:])),
            )

    authority = ProofAuthority()
    app = create_acceptance_controller_app(
        authority=authority,
        controller_token="controller-token-is-separate",
        runtime_lock_path=tmp_path / "controller-proof.lock",
    )
    headers = {"Authorization": "Bearer controller-token-is-separate"}
    with TestClient(app) as client:
        assert (
            client.post(
                "/api/internal/acceptance/proof",
                json=_proof_payload(collector_id="sealed"),
            ).status_code
            == 401
        )
        unsealed = client.post(
            "/api/internal/acceptance/proof",
            headers=headers,
            json=_proof_payload(collector_id="unsealed"),
        )
        response = client.post(
            "/api/internal/acceptance/proof",
            headers=headers,
            json=_proof_payload(collector_id="sealed"),
        )
    assert unsealed.status_code == 409
    assert response.status_code == 200
    assert response.content == proof_payload
    assert response.headers["content-length"] == str(len(proof_payload))
    assert response.headers["digest"] == (f"sha-256={hashlib.sha256(proof_payload).hexdigest()}")
    assert response.headers["x-kuzet-proof-lines"] == "2"
    assert authority.calls[-1] == (
        "proof_metadata",
        {**_proof_payload(collector_id="sealed"), "trust_binding": None},
    )


def test_compose_keeps_acceptance_authority_out_of_restartable_api() -> None:
    compose = yaml.safe_load(Path("deploy/pilot/docker-compose.yml").read_text(encoding="utf-8"))
    api = compose["services"]["api"]
    controller = compose["services"]["acceptance-controller"]
    assert "PILOT_ACCEPTANCE_JOURNAL_PATH" not in api["environment"]
    assert "acceptance_controller_token" not in api["secrets"]
    assert "ports" not in api
    assert controller["ports"] == [
        "127.0.0.1:${PILOT_ACCEPTANCE_PORT:?set-loopback-acceptance-port}:8000"
    ]
    assert controller["environment"]["PILOT_ACCEPTANCE_JOURNAL_PATH"].endswith("authority.sqlite3")
    assert (
        controller["environment"]["PILOT_ACCEPTANCE_PROOF_DIR"]
        == "/var/lib/kuzet/acceptance-proofs"
    )
    proof_mount = next(
        volume
        for volume in controller["volumes"]
        if volume.get("target") == "/var/lib/kuzet/acceptance-proofs"
    )
    assert "PILOT_ACCEPTANCE_PROOF_PATH" in proof_mount["source"]
    assert proof_mount["read_only"] is False
    assert proof_mount["bind"]["create_host_path"] is False
    assert "depends_on" not in controller
