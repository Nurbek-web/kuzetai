from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from protector.pilot.config import SiteConfig
from protector.pilot.gates import (
    ConditionalModelGateResultV1,
    OperationalGateDecisionEnvelopeV2,
)
from protector.pilot.rules import (
    CameraRuleV1,
    ReviewedCameraRulesetV1,
    ReviewedSiteConfigRevisionV1,
    VerifiedCameraRulesetRevision,
    VerifiedSiteConfigRevision,
    compile_verified_camera_rules,
    load_verified_camera_ruleset,
    load_verified_model_gate_decision,
    load_verified_site_config_revision,
)

NOW = datetime(2026, 7, 31, 9, 0, tzinfo=UTC)
FROZEN_WORKLOAD_SHA256 = "b" * 64
ENGINE_SHA256 = "c" * 64
RUNTIME_MANIFEST_SHA256 = "d" * 64
TARGET_SITE_REPORT_SHA256 = "e" * 64
MEASURED_CAPACITY_REPORT_SHA256 = "f" * 64


def _feed(number: int) -> dict[str, object]:
    return {
        "camera_id": f"camera-{number:02d}",
        "source_index": number - 1,
        "rtsp_url": {"environment": f"PILOT_CAMERA_{number:02d}_RTSP_URL"},
        "codec": "h264",
        "resolution": {"width": 1920, "height": 1080},
        "fps": 25.0,
        "bitrate_kbps": 2_000,
        "analytics_hz": {
            "person": 10.0,
            "fire_smoke": 1.0,
            "weapon": 1.0,
            "fight": 0.2,
        },
    }


def _site_config() -> SiteConfig:
    return SiteConfig.model_validate(
        {
            "ready_to_start": {
                "feeds": [_feed(number) for number in range(1, 21)],
                "ntp_source": "ntp.customer.example",
                "camera_map": "approved-map-v1",
                "site_access": "approved",
                "compute": "NVIDIA L4 pilot node",
                "notification_channel": "reviewed Telegram connector",
                "model_rights_decisions": "model-register-v1",
            },
            "storage": {
                "country_code": "KZ",
                "endpoint": "https://object-storage.customer.example",
                "bucket": "kuzet-pilot-evidence",
                "evidence_prefix": "pilot-evidence/site-1",
                "server_side_encryption": "AES256",
                "retention": {
                    "continuous_video_owner": "customer_nvr",
                    "continuous_video_storage_enabled": False,
                    "encoded_ring_buffer_seconds": 15,
                    "evidence_retention_days": 30,
                    "metadata_retention_days": 365,
                },
            },
            "queues": {
                "decode": 64,
                "analytics": 256,
                "verifier": 32,
                "events": 128,
            },
        }
    )


def _site_revision() -> ReviewedSiteConfigRevisionV1:
    return ReviewedSiteConfigRevisionV1.create(
        config_revision_id="site-config-1",
        revision=1,
        site_id="site-1",
        config=_site_config(),
        reviewed_by="customer-change-board",
        reviewed_at=NOW,
        review_reference="reviews/site-config-1.json",
    )


def _rule(
    *,
    camera_id: str = "camera-01",
    module: str = "weapon",
    mode: str = "operator",
    minimum_votes: int = 2,
    window_seconds: float = 3.0,
) -> CameraRuleV1:
    decision = _decision_envelope(module=module, mode=mode)
    return CameraRuleV1.create(
        rule_id=f"{camera_id}-{module}",
        revision=1,
        site_id="site-1",
        camera_id=camera_id,
        module=module,
        enabled=True,
        model_artifact_id=f"{module}-v1",
        model_decision_sha256=decision.authority_sha256,
        minimum_confidence=0.8,
        minimum_votes=minimum_votes,
        window_seconds=window_seconds,
        evidence_seconds=6,
    )


def _decision(
    *,
    module: str = "weapon",
    mode: str = "operator",
) -> ConditionalModelGateResultV1:
    return ConditionalModelGateResultV1(
        site_id="site-1",
        module=module,
        artifact_id=f"{module}-v1",
        registry_entry_sha256="a" * 64,
        mode=mode,
        reasons=(),
    )


def _decision_envelope(
    *,
    module: str = "weapon",
    mode: str = "operator",
    site_config_sha256: str | None = None,
    frozen_workload_sha256: str = FROZEN_WORKLOAD_SHA256,
    engine_sha256: str = ENGINE_SHA256,
    runtime_manifest_sha256: str = RUNTIME_MANIFEST_SHA256,
) -> OperationalGateDecisionEnvelopeV2:
    return OperationalGateDecisionEnvelopeV2(
        decision=_decision(module=module, mode=mode),
        site_config_sha256=site_config_sha256 or _site_revision().config_sha256,
        target_site_report_sha256=TARGET_SITE_REPORT_SHA256,
        measured_capacity_report_sha256=MEASURED_CAPACITY_REPORT_SHA256,
        frozen_workload_sha256=frozen_workload_sha256,
        engine_sha256=engine_sha256,
        runtime_manifest_sha256=runtime_manifest_sha256,
        required_effective_throughput_hz=80.0,
        measured_effective_throughput_hz=100.0,
    )


def _ruleset(*rules: CameraRuleV1) -> ReviewedCameraRulesetV1:
    site = _site_revision()
    return ReviewedCameraRulesetV1.create(
        ruleset_revision_id="ruleset-1",
        ruleset_id="controlled-pilot-rules",
        revision=1,
        site_id="site-1",
        site_config_sha256=site.config_sha256,
        frozen_workload_sha256=FROZEN_WORKLOAD_SHA256,
        engine_sha256=ENGINE_SHA256,
        runtime_manifest_sha256=RUNTIME_MANIFEST_SHA256,
        rules=rules or (_rule(),),
        reviewed_by="customer-change-board",
        reviewed_at=NOW,
        review_reference="reviews/ruleset-1.json",
    )


def _verified_inputs(
    tmp_path: Path,
    *rules: CameraRuleV1,
) -> tuple[VerifiedSiteConfigRevision, VerifiedCameraRulesetRevision]:
    site_document = _site_revision()
    site_payload = json.dumps(
        site_document.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    site_path, site_signature, site_key = _sign(tmp_path, "fixture-site", site_payload)
    rules_document = _ruleset(*rules)
    rules_payload = json.dumps(
        rules_document.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    rules_path, rules_signature, rules_key = _sign(
        tmp_path, "fixture-rules", rules_payload
    )
    return (
        load_verified_site_config_revision(
            payload_path=site_path,
            signature_path=site_signature,
            trusted_public_key_path=site_key,
            expected_payload_sha256=hashlib.sha256(site_payload).hexdigest(),
            expected_site_id="site-1",
        ),
        load_verified_camera_ruleset(
            payload_path=rules_path,
            signature_path=rules_signature,
            trusted_public_key_path=rules_key,
            expected_payload_sha256=hashlib.sha256(rules_payload).hexdigest(),
            expected_site_id="site-1",
        ),
    )


def _sign(tmp_path: Path, name: str, payload: bytes) -> tuple[Path, Path, Path]:
    payload_path = tmp_path / f"{name}.json"
    private_key = tmp_path / f"{name}.private.pem"
    public_key = tmp_path / f"{name}.public.pem"
    signature = tmp_path / f"{name}.sig"
    payload_path.write_bytes(payload)
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
            str(payload_path),
            "-out",
            str(signature),
        ],
        check=True,
        capture_output=True,
    )
    return payload_path, signature, public_key


def _verified_decision(
    tmp_path: Path,
    decision: OperationalGateDecisionEnvelopeV2,
    *,
    name: str = "fixture-decision",
):
    payload = json.dumps(
        decision.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    payload_path, signature, public_key = _sign(tmp_path, name, payload)
    return load_verified_model_gate_decision(
        payload_path=payload_path,
        signature_path=signature,
        trusted_public_key_path=public_key,
        expected_payload_sha256=hashlib.sha256(payload).hexdigest(),
        expected_site_id="site-1",
    )


def test_detached_signatures_and_exact_outer_digests_are_mandatory(tmp_path: Path) -> None:
    site_document = _site_revision()
    site_payload = json.dumps(
        site_document.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    site_path, site_signature, public_key = _sign(tmp_path, "site", site_payload)
    verified_site = load_verified_site_config_revision(
        payload_path=site_path,
        signature_path=site_signature,
        trusted_public_key_path=public_key,
        expected_payload_sha256=hashlib.sha256(site_payload).hexdigest(),
        expected_site_id="site-1",
    )
    assert verified_site.document == site_document

    ruleset_document = _ruleset()
    ruleset_payload = json.dumps(
        ruleset_document.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    rules_path, rules_signature, rules_public_key = _sign(
        tmp_path, "rules", ruleset_payload
    )
    verified_rules = load_verified_camera_ruleset(
        payload_path=rules_path,
        signature_path=rules_signature,
        trusted_public_key_path=rules_public_key,
        expected_payload_sha256=hashlib.sha256(ruleset_payload).hexdigest(),
        expected_site_id="site-1",
    )
    assert verified_rules.document == ruleset_document

    with pytest.raises(ValueError, match="unavailable|signature"):
        load_verified_camera_ruleset(
            payload_path=rules_path,
            signature_path=tmp_path / "unsigned.sig",
            trusted_public_key_path=public_key,
            expected_payload_sha256=hashlib.sha256(ruleset_payload).hexdigest(),
            expected_site_id="site-1",
        )
    with pytest.raises(ValueError, match="digest"):
        load_verified_site_config_revision(
            payload_path=site_path,
            signature_path=site_signature,
            trusted_public_key_path=public_key,
            expected_payload_sha256="0" * 64,
            expected_site_id="site-1",
        )


def test_compiler_binds_rules_to_exact_site_camera_and_verified_decision(
    tmp_path: Path,
) -> None:
    site, rules = _verified_inputs(tmp_path, _rule(camera_id="camera-01"))
    compiled = compile_verified_camera_rules(
        site_revision=site,
        ruleset_revision=rules,
        gate_decisions=(_verified_decision(tmp_path, _decision_envelope()),),
    )

    match = compiled.evaluate(
        camera_id="camera-01",
        module="weapon",
        confidence=0.91,
        votes=2,
        window_seconds=2.0,
    )
    assert match is not None
    assert match.gate_mode == "operator"
    assert match.rule_id == "camera-01-weapon"
    assert match.model_gate_decision_sha256 == _decision_envelope().authority_sha256
    assert compiled.rules[0].sample_count == 2
    assert compiled.rules[0].spec.kind == "module"
    assert (
        compiled.evaluate(
            camera_id="camera-02",
            module="weapon",
            confidence=0.99,
            votes=10,
            window_seconds=1.0,
        )
        is None
    )

    wrong_site = _ruleset().model_copy(update={"site_id": "site-2"})
    wrong_payload = json.dumps(
        wrong_site.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    wrong_path, wrong_signature, wrong_key = _sign(
        tmp_path, "wrong-site", wrong_payload
    )
    with pytest.raises(ValueError, match="site"):
        compile_verified_camera_rules(
            site_revision=site,
            ruleset_revision=load_verified_camera_ruleset(
                payload_path=wrong_path,
                signature_path=wrong_signature,
                trusted_public_key_path=wrong_key,
                expected_payload_sha256=hashlib.sha256(wrong_payload).hexdigest(),
                expected_site_id="site-2",
            ),
            gate_decisions=(
                _verified_decision(
                    tmp_path,
                    _decision_envelope(),
                    name="wrong-site-decision",
                ),
            ),
        )

    unknown_camera = _ruleset(_rule(camera_id="camera-99"))
    unknown_payload = json.dumps(
        unknown_camera.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    unknown_path, unknown_signature, unknown_key = _sign(
        tmp_path, "unknown-camera", unknown_payload
    )
    with pytest.raises(ValueError, match="camera"):
        compile_verified_camera_rules(
            site_revision=site,
            ruleset_revision=load_verified_camera_ruleset(
                payload_path=unknown_path,
                signature_path=unknown_signature,
                trusted_public_key_path=unknown_key,
                expected_payload_sha256=hashlib.sha256(unknown_payload).hexdigest(),
                expected_site_id="site-1",
            ),
            gate_decisions=(
                _verified_decision(
                    tmp_path,
                    _decision_envelope(),
                    name="unknown-camera-decision",
                ),
            ),
        )


def test_gate_mode_is_derived_and_disabled_never_emits_a_candidate(
    tmp_path: Path,
) -> None:
    disabled_decision = _decision_envelope(mode="disabled")
    disabled_rule = CameraRuleV1.create(
        rule_id="camera-01-weapon",
        revision=1,
        site_id="site-1",
        camera_id="camera-01",
        module="weapon",
        enabled=True,
        model_artifact_id="weapon-v1",
        model_decision_sha256=disabled_decision.authority_sha256,
        minimum_confidence=0.8,
        minimum_votes=1,
        window_seconds=3,
        evidence_seconds=6,
    )
    site, rules = _verified_inputs(tmp_path, disabled_rule)
    with pytest.raises(TypeError, match="verified"):
        compile_verified_camera_rules(
            site_revision=site,
            ruleset_revision=rules,
            gate_decisions=(disabled_decision,),  # type: ignore[arg-type]
        )
    compiled = compile_verified_camera_rules(
        site_revision=site,
        ruleset_revision=rules,
        gate_decisions=(
            _verified_decision(
                tmp_path, disabled_decision, name="disabled-decision"
            ),
        ),
    )
    assert (
        compiled.evaluate(
            camera_id="camera-01",
            module="weapon",
            confidence=1.0,
            votes=10,
            window_seconds=1.0,
        )
        is None
    )

    fight_rule = _rule(module="fight", mode="operator")
    site, rules = _verified_inputs(tmp_path, fight_rule)
    compiled = compile_verified_camera_rules(
        site_revision=site,
        ruleset_revision=rules,
        gate_decisions=(
            _verified_decision(
                tmp_path,
                _decision_envelope(module="fight", mode="operator"),
                name="fight-decision",
            ),
        ),
    )
    fight = compiled.evaluate(
        camera_id="camera-01",
        module="fight",
        confidence=0.99,
        votes=2,
        window_seconds=2.0,
    )
    assert fight is not None
    assert fight.gate_mode == "shadow"


def test_rules_reject_unbounded_values_and_inner_digest_tampering(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValidationError):
        _rule(minimum_votes=65)
    with pytest.raises(ValidationError):
        _rule(window_seconds=60.1)

    rule = _rule()
    with pytest.raises(ValidationError, match="digest"):
        CameraRuleV1.model_validate(
            {**rule.model_dump(mode="json"), "rule_revision_sha256": "0" * 64}
        )

    site, rules = _verified_inputs(tmp_path, rule)
    wrong_decision = _decision_envelope(mode="shadow")
    with pytest.raises(ValueError, match="decision"):
        compile_verified_camera_rules(
            site_revision=site,
            ruleset_revision=rules,
            gate_decisions=(
                _verified_decision(
                    tmp_path, wrong_decision, name="mismatched-decision"
                ),
            ),
        )
