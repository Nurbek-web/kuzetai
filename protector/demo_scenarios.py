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

CATEGORY_LABELS = {
    "benign_contact": "Без инцидентов",
    "benign_monitoring": "Без инцидентов",
    "weapon": "Оружие",
    "fire_smoke": "Дым / огонь",
    "violence": "Агрессия",
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
    DemoScenario("benign_hug", "Без ложной тревоги", "Без инцидентов", "Коридор"),
    DemoScenario("weapon_gun", "Оружие: пистолет", "Оружие", "Кампус"),
    DemoScenario("weapon_knife", "Оружие: нож", "Оружие", "Кампус"),
    DemoScenario("fire_detection", "Дым / огонь", "Дым / огонь", "Кампус"),
    DemoScenario("fight_institution", "Агрессия", "Агрессия", "Коридор A"),
    DemoScenario(
        "calm_monitoring",
        "Без инцидентов",
        "Без инцидентов",
        "Коридор A",
        include_in_reel=False,
    ),
    DemoScenario(
        "fight_hallway",
        "Агрессия: дополнительный пример",
        "Агрессия",
        "Коридор B",
        include_in_reel=False,
    ),
    DemoScenario(
        "zone_intrusion",
        "Запретная зона",
        "Запретная зона",
        "Запретная зона",
        include_in_reel=False,
    ),
    DemoScenario(
        "zone_loitering",
        "Длительное пребывание",
        "Запретная зона",
        "Запретная зона",
        include_in_reel=False,
    ),
    DemoScenario(
        "multi_finale",
        "Мультисценарий",
        "Мультисценарий",
        "Кампус",
        include_in_reel=False,
    ),
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


def iter_manifest_scenarios(manifest: dict[str, Any]) -> tuple[DemoScenario, ...]:
    scenarios: list[DemoScenario] = []
    for clip in manifest.get("clips", []):
        if clip.get("include_in_reel") is False:
            continue
        clip_id = str(clip["id"])
        category = str(clip.get("category", ""))
        scenarios.append(
            DemoScenario(
                id=clip_id,
                title=str(clip.get("title", clip_id)),
                short_label=CATEGORY_LABELS.get(category, get_scenario(clip_id).short_label),
                location=str(clip.get("location", "Кампус")),
            )
        )
    return tuple(scenarios)


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
        "Открыть карточку инцидента →"
    )


def build_scenario_summary(
    scenario_id: str,
    video_path: Path,
    log_path: Path,
    scenario: DemoScenario | None = None,
) -> dict[str, Any]:
    scenario = scenario or get_scenario(scenario_id)
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
