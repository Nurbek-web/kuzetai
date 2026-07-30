from __future__ import annotations

import hashlib
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from sqlalchemy import select

from protector.pilot.config import load_site_config
from protector.pilot.gates import (
    CapacityReportV1,
    CommercialRightsRecordV1,
    MeasuredCapacityReportV1,
    ModelArtifactV1,
    ShadowStageReportV1,
    TargetSiteReportV1,
    site_config_sha256,
)
from protector.pilot.provisioning import (
    ProvisioningError,
    load_reviewed_inputs,
    provision_reviewed_pilot,
)
from protector.pilot.runtime.deepstream import RuntimeModelManifestV1
from protector.pilot.storage.db import create_engine, create_session_factory
from protector.pilot.storage.models import Base, CameraModel, ModelArtifactModel, SiteModel

REPO_ROOT = Path(__file__).resolve().parents[2]
SITE_ID = "customer-site-1"
RUNTIME_IDENTITIES = {
    "runtime_image_id_sha256": "1" * 64,
    "runtime_image_config_sha256": "2" * 64,
    "runtime_code_sha256": "3" * 64,
    "mount_contract_sha256": "4" * 64,
}


def _sign_capacity(tmp_path: Path, capacity_path: Path) -> None:
    private_key = tmp_path / "capacity-authority-private.pem"
    public_key = tmp_path / "capacity-authority-public.pem"
    signature = tmp_path / "measured-capacity.sig"
    if not private_key.exists():
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private_key)],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(private_key),
                "-pubout",
                "-out",
                str(public_key),
            ],
            check=True,
            capture_output=True,
        )
    subprocess.run(
        [
            "openssl",
            "pkeyutl",
            "-sign",
            "-rawin",
            "-inkey",
            str(private_key),
            "-in",
            str(capacity_path),
            "-out",
            str(signature),
        ],
        check=True,
        capture_output=True,
    )


def _capacity_security(tmp_path: Path) -> dict[str, object]:
    return {
        "measured_capacity_signature_path": tmp_path / "measured-capacity.sig",
        "capacity_authority_public_key_path": (
            tmp_path / "capacity-authority-public.pem"
        ),
        **RUNTIME_IDENTITIES,
    }


def _runtime_manifest() -> RuntimeModelManifestV1:
    signed_at = datetime(2026, 7, 29, 9, 0, tzinfo=UTC)
    artifact = ModelArtifactV1(
        schema_version="model-artifact.v1",
        artifact_id="person-primary-v1",
        sha256="a" * 64,
        source="s3://kz-model-registry/person-primary-v1.onnx",
        commercial_rights=CommercialRightsRecordV1(
            schema_version="commercial-rights.v1",
            record_id="rights-person-v1",
            terms_reference="contracts/model-rights/person-primary-v1.pdf",
            commercial_use_approved=True,
        ),
        class_list=("person",),
        preprocessing="letterbox-rgb-640x640",
        analytic="person",
    )
    report = {
        "artifact_id": artifact.artifact_id,
        "passed": True,
        "report_reference": "reports/person-primary-v1.json",
        "report_sha256": "b" * 64,
        "signed_by": "pilot-qa",
        "signed_at": signed_at,
    }
    return RuntimeModelManifestV1(
        schema_version="deepstream-runtime-manifest.v1",
        site_id=SITE_ID,
        artifact=artifact,
        registry_entry_sha256="d" * 64,
        frozen_workload_sha256="e" * 64,
        expected_workload_sha256="f" * 64,
        engine_sha256="c" * 64,
        precision="fp16",
        target_compute_capability="8.9",
        tensorrt_version="10.16.0.72",
        target_site_report=TargetSiteReportV1(
            schema_version="target-site-report.v1",
            site_id=SITE_ID,
            **report,
        ),
        capacity_report=CapacityReportV1(
            schema_version="capacity-report.v1",
            stream_count=20,
            **report,
        ),
        shadow_stage_report=ShadowStageReportV1(
            schema_version="shadow-stage-report.v1",
            **report,
        ),
    )


def _reviewed_files(tmp_path: Path) -> tuple[Path, str, Path, str, Path, str]:
    site_path = tmp_path / "site.yaml"
    site_path.write_text(
        (REPO_ROOT / "configs/pilot.example.yaml")
        .read_text()
        .replace("evidence_prefix: pilot-evidence", f"evidence_prefix: pilot-evidence/{SITE_ID}")
    )
    manifest_path = tmp_path / "runtime.yaml"
    manifest_path.write_text(
        yaml.safe_dump(_runtime_manifest().model_dump(mode="json"), sort_keys=True)
    )
    site_sha256 = hashlib.sha256(site_path.read_bytes()).hexdigest()
    capacity_path = tmp_path / "measured-capacity.yaml"
    capacity_path.write_text(
        yaml.safe_dump(
            MeasuredCapacityReportV1(
                schema_version="measured-capacity-report.v1",
                site_id=SITE_ID,
                artifact_id="person-primary-v1",
                artifact_sha256="a" * 64,
                registry_entry_sha256="d" * 64,
                engine_sha256="c" * 64,
                precision="fp16",
                target_gpu_architecture="NVIDIA L4 (Ada)",
                target_compute_capability="8.9",
                tensorrt_version="10.16.0.72",
                nvidia_driver_version="575.57.08",
                cuda_driver_version="13.0",
                cuda_runtime_version="13.0",
                nvidia_container_toolkit_version="1.17.8",
                gpu_devices=(
                    {
                        "uuid": "GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                        "product_name": "NVIDIA L4",
                        "pci_bus_id": "0000:01:00.0",
                        "total_vram_bytes": 24_000_000_000,
                        "compute_capability": "8.9",
                        "mig_mode": "disabled",
                    },
                ),
                site_config_sha256=site_config_sha256(load_site_config(site_path)),
                runtime_manifest_file_sha256=hashlib.sha256(
                    manifest_path.read_bytes()
                ).hexdigest(),
                frozen_workload_sha256="e" * 64,
                expected_workload_sha256="f" * 64,
                runtime_image_id_sha256="1" * 64,
                runtime_image_config_sha256="2" * 64,
                runtime_code_sha256="3" * 64,
                mount_contract_sha256="4" * 64,
                stream_count=20,
                effective_throughput_hz=250.0,
                required_throughput_hz=200.0,
                scheduled_drop_fraction=0.005,
                queue_age_p95_seconds=0.5,
                queue_age_p99_seconds=1.0,
                gpu_utilization_max=0.7,
                vram_utilization_max=0.75,
                passed=True,
                report_reference="reports/capacity/person-primary-v1.json",
                report_sha256="9" * 64,
                signed_by="capacity-qa",
                signed_at=datetime(2026, 7, 29, 11, 0, tzinfo=UTC),
            ).model_dump(mode="json"),
            sort_keys=True,
        )
    )
    _sign_capacity(tmp_path, capacity_path)
    return (
        site_path,
        site_sha256,
        manifest_path,
        hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        capacity_path,
        hashlib.sha256(capacity_path.read_bytes()).hexdigest(),
    )


def test_reviewed_provisioning_is_digest_bound_idempotent_and_secret_free(
    tmp_path: Path,
) -> None:
    (
        site_path,
        site_sha,
        manifest_path,
        manifest_sha,
        capacity_path,
        capacity_sha,
    ) = _reviewed_files(tmp_path)
    config, manifest, _, _ = load_reviewed_inputs(
        site_id=SITE_ID,
        site_config_path=site_path,
        site_config_sha256=site_sha,
        runtime_manifest_path=manifest_path,
        runtime_manifest_sha256=manifest_sha,
        measured_capacity_path=capacity_path,
        measured_capacity_sha256=capacity_sha,
        **_capacity_security(tmp_path),
    )
    engine = create_engine(f"sqlite:///{tmp_path / 'pilot.db'}")
    Base.metadata.create_all(engine)
    sessions = create_session_factory(engine)

    for _ in range(2):
        provision_reviewed_pilot(
            session_factory=sessions,
            site_id=SITE_ID,
            site_name="Controlled Pilot",
            timezone_name="Asia/Almaty",
            site_config=config,
            runtime_manifest=manifest,
        )

    with sessions() as session:
        assert session.scalar(select(SiteModel.site_id)) == SITE_ID
        cameras = list(session.scalars(select(CameraModel).order_by(CameraModel.camera_id)))
        artifacts = list(session.scalars(select(ModelArtifactModel)))
    assert len(cameras) == 20
    assert all(row.source_reference.startswith("environment:PILOT_CAMERA_") for row in cameras)
    assert all("rtsp://" not in row.source_reference for row in cameras)
    assert [row.artifact_id for row in artifacts] == ["person-primary-v1"]

    with sessions.begin() as session:
        cameras[0] = session.get(CameraModel, "camera-01")
        assert cameras[0] is not None
        cameras[0].state = "online"
    provision_reviewed_pilot(
        session_factory=sessions,
        site_id=SITE_ID,
        site_name="Controlled Pilot",
        timezone_name="Asia/Almaty",
        site_config=config,
        runtime_manifest=manifest,
    )


def test_reviewed_provisioning_rejects_digest_or_persistent_drift(tmp_path: Path) -> None:
    (
        site_path,
        site_sha,
        manifest_path,
        manifest_sha,
        capacity_path,
        capacity_sha,
    ) = _reviewed_files(tmp_path)
    with pytest.raises(ProvisioningError, match="digest"):
        load_reviewed_inputs(
            site_id=SITE_ID,
            site_config_path=site_path,
            site_config_sha256="0" * 64,
            runtime_manifest_path=manifest_path,
            runtime_manifest_sha256=manifest_sha,
            measured_capacity_path=capacity_path,
            measured_capacity_sha256=capacity_sha,
            **_capacity_security(tmp_path),
        )
    insufficient = yaml.safe_load(capacity_path.read_text())
    insufficient["effective_throughput_hz"] = 249.99
    capacity_path.write_text(yaml.safe_dump(insufficient, sort_keys=True))
    _sign_capacity(tmp_path, capacity_path)
    insufficient_sha = hashlib.sha256(capacity_path.read_bytes()).hexdigest()
    with pytest.raises(ProvisioningError, match="25% headroom"):
        load_reviewed_inputs(
            site_id=SITE_ID,
            site_config_path=site_path,
            site_config_sha256=site_sha,
            runtime_manifest_path=manifest_path,
            runtime_manifest_sha256=manifest_sha,
            measured_capacity_path=capacity_path,
            measured_capacity_sha256=insufficient_sha,
            **_capacity_security(tmp_path),
        )
    capacity_path, capacity_sha = _reviewed_files(tmp_path)[4:]
    config, manifest, _, _ = load_reviewed_inputs(
        site_id=SITE_ID,
        site_config_path=site_path,
        site_config_sha256=site_sha,
        runtime_manifest_path=manifest_path,
        runtime_manifest_sha256=manifest_sha,
        measured_capacity_path=capacity_path,
        measured_capacity_sha256=capacity_sha,
        **_capacity_security(tmp_path),
    )
    engine = create_engine(f"sqlite:///{tmp_path / 'drift.db'}")
    Base.metadata.create_all(engine)
    sessions = create_session_factory(engine)
    provision_reviewed_pilot(
        session_factory=sessions,
        site_id=SITE_ID,
        site_name="Controlled Pilot",
        timezone_name="Asia/Almaty",
        site_config=config,
        runtime_manifest=manifest,
    )
    with sessions.begin() as session:
        session.add(
            CameraModel(
                camera_id="unreviewed-camera",
                site_id=SITE_ID,
                name="unreviewed-camera",
                source_reference="environment:UNREVIEWED_CAMERA",
                codec="h264",
                state="starting",
                enabled=False,
            )
        )
    with pytest.raises(ProvisioningError, match="camera set"):
        provision_reviewed_pilot(
            session_factory=sessions,
            site_id=SITE_ID,
            site_name="Controlled Pilot",
            timezone_name="Asia/Almaty",
            site_config=config,
            runtime_manifest=manifest,
        )


@pytest.mark.parametrize(
    "binding",
    (
        "registry_entry_sha256",
        "frozen_workload_sha256",
        "expected_workload_sha256",
    ),
)
def test_capacity_inner_bindings_are_independent_of_recomputed_outer_digest(
    tmp_path: Path,
    binding: str,
) -> None:
    (
        site_path,
        site_sha,
        manifest_path,
        manifest_sha,
        capacity_path,
        _capacity_sha,
    ) = _reviewed_files(tmp_path)
    tampered = yaml.safe_load(capacity_path.read_text())
    tampered[binding] = "0" * 64
    capacity_path.write_text(yaml.safe_dump(tampered, sort_keys=True))
    _sign_capacity(tmp_path, capacity_path)
    recomputed_outer_sha = hashlib.sha256(capacity_path.read_bytes()).hexdigest()

    with pytest.raises(ProvisioningError, match="exact bindings"):
        load_reviewed_inputs(
            site_id=SITE_ID,
            site_config_path=site_path,
            site_config_sha256=site_sha,
            runtime_manifest_path=manifest_path,
            runtime_manifest_sha256=manifest_sha,
            measured_capacity_path=capacity_path,
            measured_capacity_sha256=recomputed_outer_sha,
            **_capacity_security(tmp_path),
        )


def test_capacity_requires_out_of_band_authority_and_exact_runtime_image(
    tmp_path: Path,
) -> None:
    (
        site_path,
        site_sha,
        manifest_path,
        manifest_sha,
        capacity_path,
        capacity_sha,
    ) = _reviewed_files(tmp_path)
    security = _capacity_security(tmp_path)
    signature = security["measured_capacity_signature_path"]
    assert isinstance(signature, Path)
    signature.unlink()
    with pytest.raises(ProvisioningError, match="runtime manifest is invalid"):
        load_reviewed_inputs(
            site_id=SITE_ID,
            site_config_path=site_path,
            site_config_sha256=site_sha,
            runtime_manifest_path=manifest_path,
            runtime_manifest_sha256=manifest_sha,
            measured_capacity_path=capacity_path,
            measured_capacity_sha256=capacity_sha,
            **security,
        )

    attacker_private = tmp_path / "attacker-private.pem"
    attacker_public = tmp_path / "attacker-public.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(attacker_private)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "openssl",
            "pkey",
            "-in",
            str(attacker_private),
            "-pubout",
            "-out",
            str(attacker_public),
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "openssl",
            "pkeyutl",
            "-sign",
            "-rawin",
            "-inkey",
            str(attacker_private),
            "-in",
            str(capacity_path),
            "-out",
            str(signature),
        ],
        check=True,
        capture_output=True,
    )
    with pytest.raises(ProvisioningError, match="runtime manifest is invalid"):
        load_reviewed_inputs(
            site_id=SITE_ID,
            site_config_path=site_path,
            site_config_sha256=site_sha,
            runtime_manifest_path=manifest_path,
            runtime_manifest_sha256=manifest_sha,
            measured_capacity_path=capacity_path,
            measured_capacity_sha256=capacity_sha,
            **security,
        )

    _sign_capacity(tmp_path, capacity_path)
    with pytest.raises(ProvisioningError, match="exact bindings"):
        load_reviewed_inputs(
            site_id=SITE_ID,
            site_config_path=site_path,
            site_config_sha256=site_sha,
            runtime_manifest_path=manifest_path,
            runtime_manifest_sha256=manifest_sha,
            measured_capacity_path=capacity_path,
            measured_capacity_sha256=capacity_sha,
            **{
                **security,
                "runtime_image_id_sha256": "9" * 64,
            },
        )
