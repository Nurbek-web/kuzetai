from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class AuditResult:
    clip_id: str
    status: str
    expected_modules: list[str]
    observed_modules: list[str]
    peak_confidence_by_module: dict[str, float]
    incident_count: int
    notes: list[str]

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _normalize_modules(modules: list[str] | tuple[str, ...] | None) -> list[str]:
    return sorted({str(module) for module in (modules or []) if str(module)})


def _observed_from_log(data: dict[str, Any]) -> tuple[list[str], dict[str, float], int]:
    peaks: dict[str, float] = {}
    incidents = [item for item in data.get("incidents", []) if isinstance(item, dict)]
    for incident in incidents:
        module = str(incident.get("module", ""))
        if not module:
            continue
        confidence = float(incident.get("confidence", 0.0) or 0.0)
        peaks[module] = max(peaks.get(module, 0.0), confidence)
    return sorted(peaks), peaks, len(incidents)


def audit_log(
    clip_id: str,
    log_path: Path,
    expected_modules: list[str] | tuple[str, ...] | None,
) -> AuditResult:
    expected = _normalize_modules(expected_modules)
    data = _read_json(log_path)
    if data is None:
        return AuditResult(
            clip_id=clip_id,
            status="missing",
            expected_modules=expected,
            observed_modules=[],
            peak_confidence_by_module={},
            incident_count=0,
            notes=["event log missing or unreadable"],
        )

    observed, peaks, incident_count = _observed_from_log(data)
    missing = sorted(set(expected) - set(observed))
    unexpected = sorted(set(observed) - set(expected))
    notes: list[str] = []
    if missing:
        notes.append(f"missing expected modules: {', '.join(missing)}")
    if unexpected:
        notes.append(f"unexpected modules: {', '.join(unexpected)}")

    return AuditResult(
        clip_id=clip_id,
        status="pass" if not notes else "fail",
        expected_modules=expected,
        observed_modules=observed,
        peak_confidence_by_module=peaks,
        incident_count=incident_count,
        notes=notes,
    )


def audit_manifest_logs(
    manifest: dict[str, Any],
    annotated_dir: Path,
) -> list[AuditResult]:
    results: list[AuditResult] = []
    for clip in manifest.get("clips", []):
        clip_id = str(clip["id"])
        expected = clip.get("expected_modules", _expected_from_modules(clip.get("modules", [])))
        log_path = annotated_dir / f"{clip_id}_annotated.json"
        results.append(audit_log(clip_id, log_path, expected))
    return results


def _expected_from_modules(modules: list[str] | tuple[str, ...]) -> list[str]:
    expected = []
    for module in modules:
        if module in {"weapons", "weapon"}:
            expected.append("weapon")
        elif module == "fire_smoke":
            expected.append("fire_smoke")
        elif module == "violence":
            expected.append("violence")
    return _normalize_modules(expected)


def write_audit_report(results: list[AuditResult], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps([result.as_dict() for result in results], indent=2))


def summarize_results(results: list[AuditResult]) -> dict[str, int]:
    missing_expected = sum(
        1
        for result in results
        if any(note.startswith("missing expected modules:") for note in result.notes)
    )
    false_alarm = sum(
        1
        for result in results
        if any(note.startswith("unexpected modules:") for note in result.notes)
    )
    passed = sum(1 for result in results if result.status == "pass")
    return {
        "total": len(results),
        "passed": passed,
        "failed": len(results) - passed,
        "missing_expected": missing_expected,
        "false_alarm": false_alarm,
    }
