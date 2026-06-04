# Kuzet AI Investor Demo Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Russian investor-facing Kuzet AI replay dashboard and curate the reel around all-clear proof, incident evidence, and simulated Telegram escalation.

**Architecture:** Add a small `protector.demo_scenarios` module that turns existing annotated MP4 + JSON artifacts into scenario summaries, evidence timelines, and Telegram preview text. Update `protector.app` to render the scenario review console first and use that shared module. Update the manifest and reel builder so investor-facing copy is Russian, the output is branded as Kuzet AI, and noisy clips can be excluded from the reel.

**Tech Stack:** Python 3.12, Gradio, PyYAML, Pillow, OpenCV, pytest, existing `uv` environment.

---

## File Structure

- Create `protector/demo_scenarios.py`: scenario metadata, JSON loading, summary generation, Russian labels, Telegram demo preview.
- Create `tests/test_demo_scenarios.py`: behavior tests for all-clear summaries, incident summaries, missing logs, and selected reel clips.
- Modify `protector/app.py`: Russian Kuzet AI scenario review console as the first tab; keep live/how-it-works tabs secondary.
- Modify `protector/demo_reel.py`: Cyrillic font fallback and `include_in_reel: false` support.
- Modify `demos/clips_manifest.yaml`: Russian investor-facing titles, Kuzet AI reel name, selected scenarios, and noisy finale exclusion.

---

### Task 1: Scenario Summary Helper

**Files:**
- Create: `protector/demo_scenarios.py`
- Create: `tests/test_demo_scenarios.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_demo_scenarios.py` with tests that assert:

```python
from pathlib import Path

from protector.demo_scenarios import (
    DEMO_SCENARIOS,
    build_scenario_summary,
    iter_reel_scenarios,
)


def test_all_clear_summary_has_no_telegram_preview(tmp_path: Path):
    video = tmp_path / "calm_monitoring_annotated.mp4"
    video.write_bytes(b"video")
    log = tmp_path / "calm_monitoring_annotated.json"
    log.write_text('{"incidents": [], "total_frames": 50, "fps": 10.0}')

    summary = build_scenario_summary("calm_monitoring", video, log)

    assert summary["verdict"] == "Без инцидентов"
    assert summary["incident_count"] == 0
    assert summary["telegram_preview"] == ""
    assert summary["timeline"] == []


def test_incident_summary_builds_timeline_and_telegram_preview(tmp_path: Path):
    video = tmp_path / "fight_institution_annotated.mp4"
    video.write_bytes(b"video")
    log = tmp_path / "fight_institution_annotated.json"
    log.write_text(
        """
        {
          "incidents": [
            {
              "module": "violence",
              "start_t": 0.2,
              "end_t": 4.9,
              "reason": "xclip=0.00 vit=0.94",
              "confidence": 0.9424,
              "frame_start": 2,
              "frame_end": 49
            }
          ],
          "total_frames": 50,
          "fps": 10.0
        }
        """
    )

    summary = build_scenario_summary("fight_institution", video, log)

    assert summary["verdict"] == "Инцидент обнаружен"
    assert summary["incident_count"] == 1
    assert summary["peak_confidence"] == "94%"
    assert summary["timeline"][0]["module_label"] == "Агрессия"
    assert "Демо-предпросмотр Telegram" in summary["telegram_preview"]
    assert "Агрессия" in summary["telegram_preview"]


def test_missing_log_returns_russian_error_without_crashing(tmp_path: Path):
    video = tmp_path / "fire_detection_annotated.mp4"
    video.write_bytes(b"video")
    missing_log = tmp_path / "fire_detection_annotated.json"

    summary = build_scenario_summary("fire_detection", video, missing_log)

    assert summary["video"] == str(video)
    assert summary["verdict"] == "Журнал событий не найден"
    assert summary["timeline"] == []
    assert summary["telegram_preview"] == ""


def test_iter_reel_scenarios_excludes_noisy_finale():
    scenario_ids = [scenario.id for scenario in iter_reel_scenarios(DEMO_SCENARIOS)]

    assert "calm_monitoring" in scenario_ids
    assert "fight_institution" in scenario_ids
    assert "multi_finale" not in scenario_ids
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
uv run pytest tests/test_demo_scenarios.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'protector.demo_scenarios'`.

- [ ] **Step 3: Implement scenario helper**

Create `protector/demo_scenarios.py` with:

```python
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


MODULE_LABELS = {
    "violence": "Агрессия",
    "weapon": "Оружие",
    "fire_smoke": "Дым / огонь",
    "zone": "Запретная зона",
}


@dataclass(frozen=True)
class DemoScenario:
    id: str
    title: str
    short_label: str
    location: str
    include_in_reel: bool = True


DEMO_SCENARIOS: tuple[DemoScenario, ...] = (
    DemoScenario("calm_monitoring", "Без инцидентов", "Без инцидентов", "Коридор A"),
    DemoScenario("zone_intrusion", "Запретная зона", "Запретная зона", "Запретная зона"),
    DemoScenario("fight_institution", "Агрессия", "Агрессия", "Коридор A"),
    DemoScenario("fire_detection", "Дым / огонь", "Дым / огонь", "Кампус"),
    DemoScenario("multi_finale", "Мультисценарий", "Мультисценарий", "Кампус", include_in_reel=False),
)


def get_scenario(scenario_id: str) -> DemoScenario:
    for scenario in DEMO_SCENARIOS:
        if scenario.id == scenario_id:
            return scenario
    return DemoScenario(scenario_id, scenario_id, scenario_id, "Кампус", include_in_reel=False)


def iter_reel_scenarios(
    scenarios: tuple[DemoScenario, ...] = DEMO_SCENARIOS,
) -> tuple[DemoScenario, ...]:
    return tuple(scenario for scenario in scenarios if scenario.include_in_reel)


def _read_log(log_path: Path) -> dict[str, Any] | None:
    if not log_path.exists():
        return None
    try:
        data = json.loads(log_path.read_text())
    except (json.JSONDecodeError, OSError):
        return None
    return data if isinstance(data, dict) else None


def _format_time(value: float) -> str:
    return f"{value:05.2f}"


def _format_confidence(value: float) -> str:
    return f"{round(value * 100):.0f}%"


def _timeline(incidents: list[dict[str, Any]]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for incident in incidents[:6]:
        module = str(incident.get("module", ""))
        confidence = float(incident.get("confidence", 0.0) or 0.0)
        start_t = float(incident.get("start_t", 0.0) or 0.0)
        rows.append(
            {
                "time": _format_time(start_t),
                "module": module,
                "module_label": MODULE_LABELS.get(module, module or "Инцидент"),
                "confidence": _format_confidence(confidence),
                "reason": str(incident.get("reason", "")),
            }
        )
    return rows


def _telegram_preview(scenario: DemoScenario, first_event: dict[str, str]) -> str:
    return (
        "Kuzet AI\n"
        "Демо-предпросмотр Telegram\n\n"
        f"Обнаружено: {first_event['module_label']} · {scenario.location}\n"
        f"Уверенность: {first_event['confidence']}\n"
        f"Время: {first_event['time']}\n\n"
        "Открыть карточку инцидента ->"
    )


def build_scenario_summary(
    scenario_id: str,
    video_path: Path,
    log_path: Path,
) -> dict[str, Any]:
    scenario = get_scenario(scenario_id)
    log_data = _read_log(log_path)
    video = str(video_path) if video_path.exists() else None

    if log_data is None:
        return {
            "id": scenario.id,
            "title": scenario.title,
            "video": video,
            "verdict": "Журнал событий не найден",
            "incident_count": 0,
            "peak_confidence": "",
            "timeline": [],
            "telegram_preview": "",
            "raw_log": {"message": "Журнал событий не найден"},
        }

    incidents = [item for item in log_data.get("incidents", []) if isinstance(item, dict)]
    timeline = _timeline(incidents)
    if not incidents:
        return {
            "id": scenario.id,
            "title": scenario.title,
            "video": video,
            "verdict": "Без инцидентов",
            "incident_count": 0,
            "peak_confidence": "",
            "timeline": [],
            "telegram_preview": "",
            "raw_log": log_data,
        }

    peak = max(float(item.get("confidence", 0.0) or 0.0) for item in incidents)
    return {
        "id": scenario.id,
        "title": scenario.title,
        "video": video,
        "verdict": "Инцидент обнаружен",
        "incident_count": len(incidents),
        "peak_confidence": _format_confidence(peak),
        "timeline": timeline,
        "telegram_preview": _telegram_preview(scenario, timeline[0]) if timeline else "",
        "raw_log": log_data,
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
uv run pytest tests/test_demo_scenarios.py -v
```

Expected: PASS.

---

### Task 2: Russian Scenario Review Dashboard

**Files:**
- Modify: `protector/app.py`
- Test: `tests/test_demo_scenarios.py`

- [ ] **Step 1: Add dashboard-specific tests**

Extend `tests/test_demo_scenarios.py` with:

```python
def test_scenario_summary_has_stable_keys_for_dashboard(tmp_path: Path):
    video = tmp_path / "zone_intrusion_annotated.mp4"
    video.write_bytes(b"video")
    log = tmp_path / "zone_intrusion_annotated.json"
    log.write_text(
        """
        {
          "incidents": [
            {
              "module": "zone",
              "start_t": 4.5,
              "end_t": 4.5,
              "reason": "intrusion in zone",
              "confidence": 1.0,
              "frame_start": 45,
              "frame_end": 45
            }
          ],
          "total_frames": 50,
          "fps": 10.0
        }
        """
    )

    summary = build_scenario_summary("zone_intrusion", video, log)

    assert set(summary) == {
        "id",
        "title",
        "video",
        "verdict",
        "incident_count",
        "peak_confidence",
        "timeline",
        "telegram_preview",
        "raw_log",
    }
    assert summary["timeline"][0]["module_label"] == "Запретная зона"
```

- [ ] **Step 2: Run test to verify it fails if helper shape regresses**

Run:

```bash
uv run pytest tests/test_demo_scenarios.py -v
```

Expected: PASS if Task 1 already returned the stable keys; otherwise adjust helper before UI.

- [ ] **Step 3: Replace the first Gradio tab with Russian review console**

Modify `protector/app.py` so:

- imports `build_scenario_summary` and `iter_reel_scenarios`;
- replaces `_build_library_tab` with `_build_scenario_review_tab`;
- renders Russian header text and first tab title;
- each scenario button loads video, verdict Markdown, timeline JSON, Telegram preview text, and raw JSON log.

- [ ] **Step 4: Verify imports still work**

Run:

```bash
uv run python - <<'PY'
from protector.app import create_app
app = create_app()
print(type(app).__name__)
PY
```

Expected: prints `Blocks`.

---

### Task 3: Russian Reel Curation

**Files:**
- Modify: `demos/clips_manifest.yaml`
- Modify: `protector/demo_reel.py`
- Test: `tests/test_demo_scenarios.py`

- [ ] **Step 1: Add reel selection test**

Extend `tests/test_demo_scenarios.py` with:

```python
def test_selected_investor_reel_order_is_product_led():
    scenario_ids = [scenario.id for scenario in iter_reel_scenarios(DEMO_SCENARIOS)]

    assert scenario_ids == [
        "calm_monitoring",
        "zone_intrusion",
        "fight_institution",
        "fire_detection",
    ]
```

- [ ] **Step 2: Run test to verify it fails until scenario order is final**

Run:

```bash
uv run pytest tests/test_demo_scenarios.py::test_selected_investor_reel_order_is_product_led -v
```

Expected: FAIL if the scenario list still contains non-final reel scenarios.

- [ ] **Step 3: Update scenario metadata and manifest**

Update `DEMO_SCENARIOS` order to exactly:

```python
DEMO_SCENARIOS: tuple[DemoScenario, ...] = (
    DemoScenario("calm_monitoring", "Без инцидентов", "Без инцидентов", "Коридор A"),
    DemoScenario("zone_intrusion", "Запретная зона", "Запретная зона", "Запретная зона"),
    DemoScenario("fight_institution", "Агрессия", "Агрессия", "Коридор A"),
    DemoScenario("fire_detection", "Дым / огонь", "Дым / огонь", "Кампус"),
    DemoScenario("fight_hallway", "Агрессия: дополнительный пример", "Агрессия", "Коридор B", include_in_reel=False),
    DemoScenario("zone_loitering", "Длительное пребывание", "Запретная зона", "Запретная зона", include_in_reel=False),
    DemoScenario("multi_finale", "Мультисценарий", "Мультисценарий", "Кампус", include_in_reel=False),
)
```

Update `demos/clips_manifest.yaml` investor-facing titles to Russian, set `reel.output` to `reel/kuzet_ai_investor_reel.mp4`, opening title to `Kuzet AI`, subtitle to `ИИ-видеоаналитика для безопасности школ и кампусов`, and add `include_in_reel: false` to noisy or secondary scenarios.

- [ ] **Step 4: Add reel-builder support for `include_in_reel: false` and Cyrillic fonts**

Modify `protector/demo_reel.py` so `build_reel` skips clip entries with `include_in_reel: false`.

Add a small font helper:

```python
def _load_font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for path in (
        "/System/Library/Fonts/Helvetica.ttc",
        "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
        "/System/Library/Fonts/Supplemental/Arial.ttf",
    ):
        try:
            return ImageFont.truetype(path, size)
        except (IOError, OSError):
            continue
    return ImageFont.load_default()
```

Use `_load_font(72)` and `_load_font(32)` in `_make_title_card_frames`.

- [ ] **Step 5: Run tests**

Run:

```bash
uv run pytest tests/test_demo_scenarios.py -v
```

Expected: PASS.

---

### Task 4: Final Verification

**Files:**
- Verify all modified files.

- [ ] **Step 1: Run full unit suite**

Run:

```bash
uv run pytest tests/ -v
```

Expected: all tests pass.

- [ ] **Step 2: Launch dashboard**

Run:

```bash
uv run python -m cli serve --port 7860
```

Expected: Gradio starts on port 7860. Open `http://localhost:7860` and verify the first tab is the Russian Kuzet AI scenario review console.

- [ ] **Step 3: Smoke-check reel builder imports**

Run:

```bash
uv run python - <<'PY'
from protector.demo_reel import _make_title_card_frames
frames = _make_title_card_frames(["Kuzet AI"], 0.1, 30, 1280, 720, ["ИИ-видеоаналитика"])
print(len(frames), frames[0].shape)
PY
```

Expected: prints a positive frame count and `(720, 1280, 3)`.
