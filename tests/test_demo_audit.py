import json
from pathlib import Path

from protector.demo_audit import AuditResult, audit_log, audit_manifest_logs, summarize_results


def _write_log(path: Path, incidents: list[dict]):
    path.write_text(json.dumps({"incidents": incidents, "total_frames": 100, "fps": 25.0}))


def test_audit_log_passes_when_expected_module_is_detected(tmp_path: Path):
    log = tmp_path / "weapon_gun_annotated.json"
    _write_log(
        log,
        [
            {
                "module": "weapon",
                "confidence": 0.91,
                "start_t": 0.1,
                "end_t": 4.0,
                "reason": "weapon conf=0.91",
                "frame_start": 3,
                "frame_end": 99,
            }
        ],
    )

    result = audit_log("weapon_gun", log, expected_modules=["weapon"])

    assert result.status == "pass"
    assert result.observed_modules == ["weapon"]
    assert result.peak_confidence_by_module == {"weapon": 0.91}


def test_audit_log_catches_false_alarm_for_benign_clip(tmp_path: Path):
    log = tmp_path / "benign_hug_annotated.json"
    _write_log(
        log,
        [
            {
                "module": "violence",
                "confidence": 0.72,
                "start_t": 1.0,
                "end_t": 2.0,
                "reason": "vit=0.72",
                "frame_start": 25,
                "frame_end": 50,
            }
        ],
    )

    result = audit_log("benign_hug", log, expected_modules=[])

    assert result.status == "fail"
    assert result.notes == ["unexpected modules: violence"]


def test_audit_manifest_logs_supports_multiple_examples_per_category(tmp_path: Path):
    manifest = {
        "clips": [
            {
                "id": "fire_01",
                "category": "fire_smoke",
                "expected_modules": ["fire_smoke"],
            },
            {
                "id": "fire_02",
                "category": "fire_smoke",
                "expected_modules": ["fire_smoke"],
            },
        ]
    }
    annotated = tmp_path / "annotated"
    annotated.mkdir()
    _write_log(
        annotated / "fire_01_annotated.json",
        [{"module": "fire_smoke", "confidence": 0.8}],
    )
    _write_log(annotated / "fire_02_annotated.json", [])

    results = audit_manifest_logs(manifest, annotated)

    assert [result.clip_id for result in results] == ["fire_01", "fire_02"]
    assert [result.status for result in results] == ["pass", "fail"]
    assert results[1].notes == ["missing expected modules: fire_smoke"]


def test_summarize_results_counts_passes_missing_and_false_alarms():
    results = [
        AuditResult("a", "pass", ["fire_smoke"], ["fire_smoke"], {"fire_smoke": 0.8}, 1, []),
        AuditResult("b", "fail", ["fire_smoke"], [], {}, 0, ["missing expected modules: fire_smoke"]),
        AuditResult("c", "fail", [], ["violence"], {"violence": 0.7}, 1, ["unexpected modules: violence"]),
    ]

    summary = summarize_results(results)

    assert summary == {
        "total": 3,
        "passed": 1,
        "failed": 2,
        "missing_expected": 1,
        "false_alarm": 1,
    }
