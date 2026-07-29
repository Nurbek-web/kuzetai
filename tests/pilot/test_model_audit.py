from __future__ import annotations

import hashlib
import json
import subprocess
import time
from pathlib import Path

import pytest
from pydantic import ValidationError

import protector.pilot.model_registry as model_registry
from protector.pilot.model_registry import (
    CalibrationCorpusV1,
    EngineBuildError,
    EngineBuildSpecV1,
    ModelRegistryEntryV1,
    NoRegressionEventReportV1,
    TargetRuntimeIdentityV1,
    audit_model_entry,
    build_engine,
    load_model_entry,
    parse_tensorrt_runtime_banner,
)


def _write_onnx(tmp_path: Path) -> tuple[Path, str]:
    artifact = tmp_path / "candidate.onnx"
    artifact.write_bytes(b"rights-cleared-onnx")
    return artifact, hashlib.sha256(artifact.read_bytes()).hexdigest()


def _entry_payload(artifact_sha256: str) -> dict[str, object]:
    return {
        "schema_version": "model-registry-entry.v1",
        "site_id": "school-01",
        "module": "weapon",
        "artifact_id": "weapon-rfdetr-2026-07-29",
        "source_uri": "s3://kz-model-registry/weapon-rfdetr-2026-07-29.onnx",
        "artifact_sha256": artifact_sha256,
        "commercial_rights": {
            "schema_version": "commercial-rights-evidence.v1",
            "status": "approved",
            "evidence_reference": "contracts/model-rights/weapon-2026-07-29.pdf",
            "evidence_sha256": "b" * 64,
            "approved_by": "legal@example.kz",
            "approved_at": "2026-07-29T08:00:00Z",
        },
        "classes": ["handgun", "long_gun", "knife"],
        "preprocessing": "letterbox-rgb-nchw-640-normalized-0-1",
        "training_provenance": "registry://training/weapon-rfdetr/run-0042",
        "evaluation_provenance": "registry://evaluation/weapon-rfdetr/site-baseline-v3",
        "thresholds": {
            "candidate_confidence": 0.62,
            "verifier_trigger_confidence": 0.78,
        },
        "engine": {
            "schema_version": "engine-record.v1",
            "engine_sha256": "e" * 64,
            "tensorrt_version": "10.16.0.72",
            "target_gpu_architecture": "NVIDIA L4 (Ada)",
            "target_compute_capability": "8.9",
            "precision": "fp16",
        },
    }


def _entry(artifact_sha256: str) -> ModelRegistryEntryV1:
    return ModelRegistryEntryV1.model_validate(_entry_payload(artifact_sha256))


def _compatible_runtime_probe(_: Path) -> TargetRuntimeIdentityV1:
    return TargetRuntimeIdentityV1(
        target_gpu_architecture="NVIDIA L4 (Ada)",
        target_compute_capability="8.9",
        tensorrt_version="10.16.0.72",
        tensorrt_runtime_version="10.16.0",
        raw_tensorrt_banner="&&&& RUNNING TensorRT.trtexec [TensorRT v101600]",
    )


def _int8_spec(
    entry: ModelRegistryEntryV1,
    *,
    calibration_sha256: str,
    candidate_engine_sha256: str | None = None,
) -> EngineBuildSpecV1:
    candidate_digest = candidate_engine_sha256 or hashlib.sha256(
        b"target-l4-engine"
    ).hexdigest()
    calibration = CalibrationCorpusV1(
        schema_version="calibration-corpus.v1",
        corpus_id="school-01-calibration",
        version="2026-07-29.1",
        sha256=calibration_sha256,
        reference="s3://kz-pilot-calibration/school-01/2026-07-29.1.cache",
    )
    report = NoRegressionEventReportV1(
        schema_version="no-regression-event-report.v1",
        artifact_id=entry.artifact_id,
        artifact_sha256=entry.artifact_sha256,
        registry_entry_sha256=entry.registry_entry_sha256,
        candidate_engine_sha256=candidate_digest,
        precision="int8",
        target_gpu_architecture="NVIDIA L4 (Ada)",
        target_compute_capability="8.9",
        tensorrt_version="10.16.0.72",
        calibration_corpus_id=calibration.corpus_id,
        calibration_corpus_version=calibration.version,
        calibration_corpus_sha256=calibration.sha256,
        passed=True,
        report_reference="reports/int8/weapon-2026-07-29.json",
        report_sha256="d" * 64,
        signed_by="site-qa@example.kz",
        signed_at="2026-07-29T10:00:00Z",
    )
    return EngineBuildSpecV1(
        precision="int8",
        calibration_corpus=calibration,
        no_regression_report=report,
    )


def _make_fake_trtexec(
    tmp_path: Path,
    *,
    exit_code: int = 0,
    noisy: bool = False,
    write_engine: bool = True,
    sleep_seconds: float = 0.0,
    name: str = "fake-trtexec",
    engine_bytes: bytes = b"target-l4-engine",
    concurrent_output: Path | None = None,
) -> Path:
    executable = tmp_path / name
    executable.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                "import pathlib",
                "import sys",
                "import time",
                "save = next(arg.split('=', 1)[1] for arg in sys.argv if arg.startswith('--saveEngine='))",
                f"time.sleep({sleep_seconds!r})",
                f"if {write_engine!r}: pathlib.Path(save).write_bytes({engine_bytes!r})",
                (
                    f"pathlib.Path({str(concurrent_output)!r}).write_bytes(b'concurrent-engine')"
                    if concurrent_output is not None
                    else ""
                ),
                f"print({'x' * 8192!r} if {noisy!r} else 'engine built')",
                f"raise SystemExit({exit_code})",
            ]
        ),
        encoding="utf-8",
    )
    executable.chmod(0o755)
    return executable


def _make_artifact_copying_trtexec(tmp_path: Path) -> Path:
    executable = tmp_path / "artifact-copying-trtexec"
    executable.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                "import pathlib",
                "import sys",
                "source = next(arg.split('=', 1)[1] for arg in sys.argv if arg.startswith('--onnx='))",
                "output = next(arg.split('=', 1)[1] for arg in sys.argv if arg.startswith('--saveEngine='))",
                "pathlib.Path(output).write_bytes(pathlib.Path(source).read_bytes())",
            ]
        ),
        encoding="utf-8",
    )
    executable.chmod(0o755)
    return executable


def _make_descendant_mutating_trtexec(tmp_path: Path) -> Path:
    executable = tmp_path / "descendant-mutating-trtexec"
    executable.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                "import pathlib",
                "import subprocess",
                "import sys",
                "import time",
                "output = next(arg.split('=', 1)[1] for arg in sys.argv if arg.startswith('--saveEngine='))",
                "pathlib.Path(output).write_bytes(b'target-l4-engine')",
                "marker = output + '.opened'",
                "code = (",
                "    \"import pathlib,time; \"",
                "    f\"handle=open({output!r}, 'r+b'); \"",
                "    f\"pathlib.Path({marker!r}).write_text('opened'); \"",
                "    \"time.sleep(0.35); handle.seek(0); \"",
                "    \"handle.write(b'tampered-engine!'); handle.flush(); handle.close()\"",
                ")",
                "subprocess.Popen(",
                "    [sys.executable, '-c', code],",
                "    stdin=subprocess.DEVNULL,",
                "    stdout=subprocess.DEVNULL,",
                "    stderr=subprocess.DEVNULL,",
                ")",
                "deadline = time.monotonic() + 2",
                "while not pathlib.Path(marker).exists() and time.monotonic() < deadline:",
                "    time.sleep(0.01)",
            ]
        ),
        encoding="utf-8",
    )
    executable.chmod(0o755)
    return executable


def test_complete_registry_entry_audits_exact_file_and_records_required_provenance(
    tmp_path: Path,
) -> None:
    artifact, digest = _write_onnx(tmp_path)
    engine_path = tmp_path / "candidate.engine"
    engine_path.write_bytes(b"existing-target-engine")
    entry = _entry(digest).model_copy(
        update={
            "engine": _entry(digest).engine.model_copy(
                update={
                    "engine_sha256": hashlib.sha256(engine_path.read_bytes()).hexdigest()
                }
            )
        }
    )

    result = audit_model_entry(entry, artifact, engine_path=engine_path)

    assert result.approved_for_export is True
    assert result.approved_for_deployment is True
    assert result.reasons == ()
    assert result.record == {
        "artifact_id": "weapon-rfdetr-2026-07-29",
        "artifact_sha256": digest,
        "classes": ["handgun", "long_gun", "knife"],
        "commercial_rights_evidence": {
            "approved_at": "2026-07-29T08:00:00Z",
            "approved_by": "legal@example.kz",
            "evidence_reference": "contracts/model-rights/weapon-2026-07-29.pdf",
            "evidence_sha256": "b" * 64,
            "status": "approved",
        },
        "engine": {
            "engine_sha256": hashlib.sha256(engine_path.read_bytes()).hexdigest(),
            "precision": "fp16",
            "schema_version": "engine-record.v1",
            "target_compute_capability": "8.9",
            "target_gpu_architecture": "NVIDIA L4 (Ada)",
            "tensorrt_version": "10.16.0.72",
        },
        "evaluation_provenance": "registry://evaluation/weapon-rfdetr/site-baseline-v3",
        "module": "weapon",
        "preprocessing": "letterbox-rgb-nchw-640-normalized-0-1",
        "registry_entry_sha256": entry.registry_entry_sha256,
        "site_id": "school-01",
        "source_uri": "s3://kz-model-registry/weapon-rfdetr-2026-07-29.onnx",
        "thresholds": {
            "candidate_confidence": 0.62,
            "verifier_trigger_confidence": 0.78,
        },
        "training_provenance": "registry://training/weapon-rfdetr/run-0042",
    }


def test_source_artifact_can_pass_export_preflight_before_an_engine_exists(
    tmp_path: Path,
) -> None:
    artifact, digest = _write_onnx(tmp_path)
    entry = _entry(digest).model_copy(update={"engine": None})

    result = audit_model_entry(entry, artifact)

    assert result.approved_for_export is True
    assert result.export_reasons == ()
    assert result.approved_for_deployment is False
    assert result.deployment_reasons == ("missing engine sha256",)


def test_audit_never_approves_unhashed_source_or_unverified_engine_bytes(
    tmp_path: Path,
) -> None:
    artifact, digest = _write_onnx(tmp_path)
    entry = _entry(digest)

    no_source_bytes = audit_model_entry(entry, artifact_path=None)
    no_engine_bytes = audit_model_entry(entry, artifact_path=artifact)
    mismatched_engine = tmp_path / "mismatched.engine"
    mismatched_engine.write_bytes(b"not-the-registered-engine")
    mismatch = audit_model_entry(entry, artifact_path=artifact, engine_path=mismatched_engine)

    assert no_source_bytes.approved_for_export is False
    assert "artifact file is required for hash audit" in no_source_bytes.export_reasons
    assert no_engine_bytes.approved_for_export is True
    assert no_engine_bytes.approved_for_deployment is False
    assert "engine file is required for deployment audit" in no_engine_bytes.deployment_reasons
    assert mismatch.approved_for_deployment is False
    assert "engine sha256 mismatch" in mismatch.deployment_reasons


@pytest.mark.parametrize("status", ["unknown", "ambiguous", "rejected"])
def test_nonapproved_rights_fail_before_exporter_or_output_side_effect(
    tmp_path: Path, status: str
) -> None:
    artifact, digest = _write_onnx(tmp_path)
    payload = _entry_payload(digest)
    payload["commercial_rights"] = {
        "schema_version": "commercial-rights-evidence.v1",
        "status": status,
    }
    output = tmp_path / "not-created" / "candidate.engine"

    with pytest.raises(EngineBuildError, match="commercial rights"):
        build_engine(
            ModelRegistryEntryV1.model_validate(payload),
            artifact_path=artifact,
            output_path=output,
            build_spec=EngineBuildSpecV1(),
            trtexec_path=tmp_path / "does-not-exist",
        )

    assert not output.parent.exists()


def test_artifact_hash_mismatch_fails_before_exporter_lookup(tmp_path: Path) -> None:
    artifact, _ = _write_onnx(tmp_path)
    output = tmp_path / "not-created" / "candidate.engine"

    with pytest.raises(EngineBuildError, match="artifact sha256 mismatch"):
        build_engine(
            _entry("a" * 64),
            artifact_path=artifact,
            output_path=output,
            build_spec=EngineBuildSpecV1(),
            trtexec_path=tmp_path / "does-not-exist",
        )

    assert not output.parent.exists()


def test_export_consumes_attested_bytes_when_source_path_changes_after_preflight(
    tmp_path: Path,
) -> None:
    artifact, digest = _write_onnx(tmp_path)
    output = tmp_path / "build" / "weapon.engine"

    def replace_source_after_preflight(_: Path) -> TargetRuntimeIdentityV1:
        replacement = tmp_path / "replacement.onnx"
        replacement.write_bytes(b"unapproved-replacement-onnx")
        replacement.replace(artifact)
        return _compatible_runtime_probe(Path("unused"))

    result = build_engine(
        _entry(digest),
        artifact_path=artifact,
        output_path=output,
        build_spec=EngineBuildSpecV1(),
        trtexec_path=_make_artifact_copying_trtexec(tmp_path),
        runtime_probe=replace_source_after_preflight,
        timeout_seconds=10,
        max_output_bytes=1024,
    )

    assert output.read_bytes() == b"rights-cleared-onnx"
    assert result.engine_sha256 == hashlib.sha256(b"rights-cleared-onnx").hexdigest()


def test_export_rejects_a_symlink_even_when_target_bytes_match(tmp_path: Path) -> None:
    artifact, digest = _write_onnx(tmp_path)
    symlink = tmp_path / "candidate-link.onnx"
    symlink.symlink_to(artifact)

    with pytest.raises(EngineBuildError, match="regular file"):
        build_engine(
            _entry(digest),
            artifact_path=symlink,
            output_path=tmp_path / "build" / "weapon.engine",
            build_spec=EngineBuildSpecV1(),
            trtexec_path=_make_fake_trtexec(tmp_path),
            runtime_probe=_compatible_runtime_probe,
        )


def test_fp16_build_uses_target_l4_argv_and_records_engine_identity(tmp_path: Path) -> None:
    artifact, digest = _write_onnx(tmp_path)
    executable = _make_fake_trtexec(tmp_path)
    output = tmp_path / "build" / "weapon.engine"

    result = build_engine(
        _entry(digest),
        artifact_path=artifact,
        output_path=output,
        build_spec=EngineBuildSpecV1(),
        trtexec_path=executable,
        runtime_probe=_compatible_runtime_probe,
        timeout_seconds=10,
        max_output_bytes=1024,
    )

    assert output.read_bytes() == b"target-l4-engine"
    assert result.precision == "fp16"
    assert result.target_gpu_architecture == "NVIDIA L4 (Ada)"
    assert result.target_compute_capability == "8.9"
    assert result.tensorrt_version == "10.16.0.72"
    assert result.engine_sha256 == hashlib.sha256(b"target-l4-engine").hexdigest()
    assert result.target_host_attested is False
    assert result.capacity_attested is False
    assert result.argv[0] == str(executable)
    onnx_argument = next(
        argument for argument in result.argv if argument.startswith("--onnx=")
    )
    assert onnx_argument != f"--onnx={artifact}"
    assert onnx_argument.endswith("/attested-model.onnx")
    assert "--fp16" in result.argv
    assert not any(argument in {"sh", "bash", "-c"} for argument in result.argv)


def test_runtime_probe_refuses_non_l4_or_tensorrt_mismatch_before_build_side_effect(
    tmp_path: Path,
) -> None:
    artifact, digest = _write_onnx(tmp_path)
    output = tmp_path / "not-created" / "weapon.engine"

    def wrong_runtime(_: Path) -> TargetRuntimeIdentityV1:
        return TargetRuntimeIdentityV1(
            target_gpu_architecture="NVIDIA RTX 4090",
            target_compute_capability="8.9",
            tensorrt_version="10.16.0.72",
            tensorrt_runtime_version="10.16.0",
            raw_tensorrt_banner="TensorRT v101600",
        )

    with pytest.raises(EngineBuildError, match="GPU architecture"):
        build_engine(
            _entry(digest),
            artifact_path=artifact,
            output_path=output,
            build_spec=EngineBuildSpecV1(),
            trtexec_path=_make_fake_trtexec(tmp_path),
            runtime_probe=wrong_runtime,
        )

    assert not output.parent.exists()


@pytest.mark.parametrize(
    ("banner", "expected"),
    [
        ("&&&& RUNNING TensorRT.trtexec [TensorRT v101600]", "10.16.0"),
        ("TensorRT v100800", "10.8.0"),
        ("TensorRT v8603", "8.6.3"),
        ("TensorRT version 10.16.0", "10.16.0"),
    ],
)
def test_tensorrt_probe_parses_dotted_and_compact_nvidia_versions(
    banner: str, expected: str
) -> None:
    assert parse_tensorrt_runtime_banner(banner) == expected


def test_tensorrt_probe_rejects_unparseable_or_semantically_mismatched_runtime(
    tmp_path: Path,
) -> None:
    with pytest.raises(EngineBuildError, match="invalid version"):
        parse_tensorrt_runtime_banner("TensorRT unknown")

    def wrong_tensorrt(_: Path) -> TargetRuntimeIdentityV1:
        return TargetRuntimeIdentityV1(
            target_gpu_architecture="NVIDIA L4 (Ada)",
            target_compute_capability="8.9",
            tensorrt_version="10.16.0.72",
            tensorrt_runtime_version="10.8.0",
            raw_tensorrt_banner="TensorRT v100800",
        )

    artifact, digest = _write_onnx(tmp_path)
    entry = _entry(digest)
    with pytest.raises(EngineBuildError, match="runtime semantic version"):
        build_engine(
            entry,
            artifact_path=artifact,
            output_path=tmp_path / "not-created" / "candidate.engine",
            build_spec=EngineBuildSpecV1(),
            trtexec_path=_make_fake_trtexec(tmp_path),
            runtime_probe=wrong_tensorrt,
        )


def test_failed_or_oververbose_export_never_publishes_a_partial_engine(tmp_path: Path) -> None:
    artifact, digest = _write_onnx(tmp_path)
    output = tmp_path / "build" / "weapon.engine"

    with pytest.raises(EngineBuildError, match="output limit"):
        build_engine(
            _entry(digest),
            artifact_path=artifact,
            output_path=output,
            build_spec=EngineBuildSpecV1(),
            trtexec_path=_make_fake_trtexec(tmp_path, noisy=True),
            runtime_probe=_compatible_runtime_probe,
            timeout_seconds=10,
            max_output_bytes=256,
        )

    assert not output.exists()


def test_exporter_descendant_cannot_mutate_published_engine_after_success(
    tmp_path: Path,
) -> None:
    artifact, digest = _write_onnx(tmp_path)
    output = tmp_path / "build" / "weapon.engine"

    result = build_engine(
        _entry(digest),
        artifact_path=artifact,
        output_path=output,
        build_spec=EngineBuildSpecV1(),
        trtexec_path=_make_descendant_mutating_trtexec(tmp_path),
        runtime_probe=_compatible_runtime_probe,
        timeout_seconds=10,
        max_output_bytes=1024,
    )
    time.sleep(0.5)

    assert output.read_bytes() == b"target-l4-engine"
    assert result.engine_sha256 == hashlib.sha256(output.read_bytes()).hexdigest()


def test_engine_publication_is_no_clobber_and_enforces_a_finite_byte_ceiling(
    tmp_path: Path,
) -> None:
    artifact, digest = _write_onnx(tmp_path)
    output = tmp_path / "build" / "weapon.engine"
    output.parent.mkdir()
    concurrent_exporter = _make_fake_trtexec(
        tmp_path,
        name="concurrent-trtexec",
        concurrent_output=output,
    )

    with pytest.raises(EngineBuildError, match="concurrent engine publication"):
        build_engine(
            _entry(digest),
            artifact_path=artifact,
            output_path=output,
            build_spec=EngineBuildSpecV1(),
            trtexec_path=concurrent_exporter,
            runtime_probe=_compatible_runtime_probe,
            timeout_seconds=10,
            max_output_bytes=1024,
        )
    assert output.read_bytes() == b"concurrent-engine"

    output.unlink()
    with pytest.raises(EngineBuildError, match="engine byte limit"):
        build_engine(
            _entry(digest),
            artifact_path=artifact,
            output_path=output,
            build_spec=EngineBuildSpecV1(),
            trtexec_path=_make_fake_trtexec(
                tmp_path,
                name="oversized-trtexec",
                engine_bytes=b"too-large-engine",
            ),
            runtime_probe=_compatible_runtime_probe,
            timeout_seconds=10,
            max_output_bytes=1024,
            max_engine_bytes=4,
        )
    assert not output.exists()


def test_publication_durability_failure_removes_destination_and_allows_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact, digest = _write_onnx(tmp_path)
    output = tmp_path / "build" / "weapon.engine"
    original_fsync_directory = model_registry._fsync_directory
    calls = 0

    def fail_first_directory_fsync(path: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("simulated parent directory fsync failure")
        original_fsync_directory(path)

    monkeypatch.setattr(model_registry, "_fsync_directory", fail_first_directory_fsync)
    with pytest.raises(EngineBuildError, match="publication durability"):
        build_engine(
            _entry(digest),
            artifact_path=artifact,
            output_path=output,
            build_spec=EngineBuildSpecV1(),
            trtexec_path=_make_fake_trtexec(tmp_path),
            runtime_probe=_compatible_runtime_probe,
            timeout_seconds=10,
            max_output_bytes=1024,
        )

    assert not output.exists()
    assert calls >= 2

    monkeypatch.setattr(model_registry, "_fsync_directory", original_fsync_directory)
    result = build_engine(
        _entry(digest),
        artifact_path=artifact,
        output_path=output,
        build_spec=EngineBuildSpecV1(),
        trtexec_path=_make_fake_trtexec(tmp_path, name="retry-trtexec"),
        runtime_probe=_compatible_runtime_probe,
        timeout_seconds=10,
        max_output_bytes=1024,
    )
    assert output.is_file()
    assert result.engine_sha256 == hashlib.sha256(output.read_bytes()).hexdigest()


@pytest.mark.parametrize(
    ("executable_options", "expected_error"),
    [
        ({"exit_code": 7, "name": "nonzero-trtexec"}, "exited with status 7"),
        ({"write_engine": False, "name": "missing-engine-trtexec"}, "did not produce an engine"),
        ({"sleep_seconds": 2.0, "name": "timeout-trtexec"}, "timed out"),
    ],
)
def test_export_failures_leave_no_published_engine(
    tmp_path: Path,
    executable_options: dict[str, object],
    expected_error: str,
) -> None:
    artifact, digest = _write_onnx(tmp_path)
    output = tmp_path / "build" / "weapon.engine"

    with pytest.raises(EngineBuildError, match=expected_error):
        build_engine(
            _entry(digest),
            artifact_path=artifact,
            output_path=output,
            build_spec=EngineBuildSpecV1(),
            trtexec_path=_make_fake_trtexec(tmp_path, **executable_options),
            runtime_probe=_compatible_runtime_probe,
            timeout_seconds=0.1 if "sleep_seconds" in executable_options else 10,
            max_output_bytes=1024,
        )

    assert not output.exists()


def test_int8_requires_exact_calibration_and_no_regression_bindings_before_export(
    tmp_path: Path,
) -> None:
    artifact, digest = _write_onnx(tmp_path)
    executable = _make_fake_trtexec(tmp_path)
    output = tmp_path / "not-created" / "weapon.engine"
    base = _entry(digest)
    incomplete_entry = base.model_copy(
        update={"engine": base.engine.model_copy(update={"precision": "int8"})}
    )
    incomplete = EngineBuildSpecV1(precision="int8")

    with pytest.raises(EngineBuildError, match="calibration corpus"):
        build_engine(
            incomplete_entry,
            artifact_path=artifact,
            output_path=output,
            build_spec=incomplete,
            trtexec_path=executable,
        )

    assert not output.parent.exists()

    calibration_path = tmp_path / "school-01-calibration.cache"
    calibration_path.write_bytes(b"school-01-calibration-cache")
    calibration_sha256 = hashlib.sha256(calibration_path.read_bytes()).hexdigest()
    candidate_engine_sha256 = hashlib.sha256(b"target-l4-engine").hexdigest()
    int8_entry = base.model_copy(
        update={
            "engine": base.engine.model_copy(
                update={
                    "precision": "int8",
                    "engine_sha256": candidate_engine_sha256,
                    "calibration_corpus_sha256": calibration_sha256,
                    "no_regression_report_sha256": "d" * 64,
                    "no_regression_candidate_engine_sha256": (
                        candidate_engine_sha256
                    ),
                }
            )
        }
    )
    spec = _int8_spec(
        int8_entry,
        calibration_sha256=calibration_sha256,
        candidate_engine_sha256=candidate_engine_sha256,
    )
    result = build_engine(
        int8_entry,
        artifact_path=artifact,
        output_path=tmp_path / "int8" / "weapon.engine",
        build_spec=spec,
        trtexec_path=executable,
        calibration_path=calibration_path,
        runtime_probe=_compatible_runtime_probe,
        timeout_seconds=10,
        max_output_bytes=1024,
    )

    assert result.precision == "int8"
    assert "--int8" in result.argv
    assert any(argument.startswith("--calib=") for argument in result.argv)

    changed_entry = int8_entry.model_copy(
        update={"thresholds": {"candidate_confidence": 0.99}}
    )
    with pytest.raises(EngineBuildError, match="registry identity"):
        build_engine(
            changed_entry,
            artifact_path=artifact,
            output_path=tmp_path / "changed" / "weapon.engine",
            build_spec=spec,
            trtexec_path=executable,
            calibration_path=calibration_path,
        )

    mismatched_output = tmp_path / "different" / "weapon.engine"
    with pytest.raises(EngineBuildError, match="candidate engine"):
        build_engine(
            int8_entry,
            artifact_path=artifact,
            output_path=mismatched_output,
            build_spec=spec,
            trtexec_path=_make_fake_trtexec(
                tmp_path,
                name="different-int8-trtexec",
                engine_bytes=b"different-int8-engine",
            ),
            calibration_path=calibration_path,
            runtime_probe=_compatible_runtime_probe,
        )
    assert not mismatched_output.exists()


def test_registry_precision_mismatch_fails_before_export_launch(tmp_path: Path) -> None:
    artifact, digest = _write_onnx(tmp_path)
    entry = _entry(digest)
    calibration_bytes = b"school-01-calibration-cache"
    spec = _int8_spec(
        entry,
        calibration_sha256=hashlib.sha256(calibration_bytes).hexdigest(),
    )
    output = tmp_path / "not-created" / "weapon.engine"

    with pytest.raises(EngineBuildError, match="registry precision"):
        build_engine(
            entry,
            artifact_path=artifact,
            output_path=output,
            build_spec=spec,
            trtexec_path=_make_fake_trtexec(tmp_path),
            runtime_probe=_compatible_runtime_probe,
        )

    assert not output.parent.exists()


def test_int8_metadata_without_exact_local_calibration_bytes_cannot_launch(
    tmp_path: Path,
) -> None:
    artifact, digest = _write_onnx(tmp_path)
    base = _entry(digest)
    calibration_bytes = b"school-01-calibration-cache"
    calibration_sha256 = hashlib.sha256(calibration_bytes).hexdigest()
    candidate_engine_sha256 = hashlib.sha256(b"target-l4-engine").hexdigest()
    entry = base.model_copy(
        update={
            "engine": base.engine.model_copy(
                update={
                    "precision": "int8",
                    "engine_sha256": candidate_engine_sha256,
                    "calibration_corpus_sha256": calibration_sha256,
                    "no_regression_report_sha256": "d" * 64,
                    "no_regression_candidate_engine_sha256": (
                        candidate_engine_sha256
                    ),
                }
            )
        }
    )
    spec = _int8_spec(
        entry,
        calibration_sha256=calibration_sha256,
    )
    output = tmp_path / "not-created" / "weapon.engine"

    with pytest.raises(EngineBuildError, match="local calibration"):
        build_engine(
            entry,
            artifact_path=artifact,
            output_path=output,
            build_spec=spec,
            trtexec_path=_make_fake_trtexec(tmp_path),
            runtime_probe=_compatible_runtime_probe,
        )

    assert not output.parent.exists()


@pytest.mark.parametrize(
    ("field", "unsafe_reference"),
    [
        ("source_uri", "https://user:secret@models.example.kz/model.onnx"),
        ("source_uri", "https://models.example.kz/model.onnx?X-Amz-Signature=secret"),
        ("source_uri", "s3://kz-model-registry/model.onnx#temporary-token"),
        ("training_provenance", "registry://training/run-7\nAuthorization: bearer-secret"),
        ("evaluation_provenance", "registry://evaluation/run-7?token=secret"),
    ],
)
def test_registry_rejects_secret_bearing_or_noncanonical_references(
    field: str,
    unsafe_reference: str,
) -> None:
    payload = _entry_payload("a" * 64)
    payload[field] = unsafe_reference

    with pytest.raises(ValidationError, match="credential-free"):
        ModelRegistryEntryV1.model_validate(payload)


def test_rights_and_int8_evidence_references_reject_signed_or_fragmented_urls() -> None:
    payload = _entry_payload("a" * 64)
    rights = dict(payload["commercial_rights"])
    rights["evidence_reference"] = "https://legal.example.kz/rights.pdf?token=secret"
    payload["commercial_rights"] = rights
    with pytest.raises(ValidationError, match="credential-free"):
        ModelRegistryEntryV1.model_validate(payload)

    with pytest.raises(ValidationError, match="credential-free"):
        CalibrationCorpusV1(
            schema_version="calibration-corpus.v1",
            corpus_id="school-01",
            version="v1",
            sha256="a" * 64,
            reference="s3://kz-calibration/school-01.cache#signed-secret",
        )


@pytest.mark.parametrize(
    "config_name",
    ["fire_candidate.yaml", "weapon_candidate.yaml"],
)
def test_checked_in_candidate_configs_are_explicit_fail_closed_placeholders(
    config_name: str,
) -> None:
    entry = load_model_entry(Path("configs/models") / config_name)

    result = audit_model_entry(entry, artifact_path=None)

    assert result.approved_for_export is False
    assert "commercial rights status is unknown" in result.reasons
    assert "missing artifact sha256" in result.reasons
    assert "missing engine sha256" in result.reasons


def test_model_audit_cli_emits_machine_readable_refusal(tmp_path: Path) -> None:
    output = tmp_path / "audit.json"
    completed = subprocess.run(
        [
            "uv",
            "run",
            "python",
            "scripts/pilot/model_audit.py",
            "--manifest",
            "configs/models/fire_candidate.yaml",
            "--out",
            str(output),
        ],
        check=False,
    )

    assert completed.returncode == 2
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["approved_for_export"] is False
    assert payload["schema_version"] == "model-audit-result.v1"
