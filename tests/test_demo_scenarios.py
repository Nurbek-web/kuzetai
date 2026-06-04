from pathlib import Path

from protector.demo_scenarios import (
    DEMO_SCENARIOS,
    DemoScenario,
    build_scenario_summary,
    get_scenario,
    iter_manifest_scenarios,
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

    assert "benign_hug" in scenario_ids
    assert "weapon_gun" in scenario_ids
    assert "weapon_knife" in scenario_ids
    assert "fight_institution" in scenario_ids
    assert "zone_intrusion" not in scenario_ids
    assert "multi_finale" not in scenario_ids


def test_scenario_summary_has_stable_keys_for_dashboard(tmp_path: Path):
    video = tmp_path / "weapon_gun_annotated.mp4"
    video.write_bytes(b"video")
    log = tmp_path / "weapon_gun_annotated.json"
    log.write_text(
        """
        {
          "incidents": [
            {
              "module": "weapon",
              "start_t": 0.2,
              "end_t": 5.9,
              "reason": "weapon conf=0.92",
              "confidence": 0.916,
              "frame_start": 5,
              "frame_end": 149
            }
          ],
          "total_frames": 150,
          "fps": 25.0
        }
        """
    )

    summary = build_scenario_summary("weapon_gun", video, log)

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
    assert summary["timeline"][0]["module_label"] == "Оружие"


def test_selected_investor_reel_order_is_product_led():
    scenario_ids = [scenario.id for scenario in iter_reel_scenarios(DEMO_SCENARIOS)]

    assert scenario_ids == [
        "benign_hug",
        "weapon_gun",
        "weapon_knife",
        "fire_detection",
        "fight_institution",
    ]


def test_secondary_scenarios_keep_russian_labels_but_stay_out_of_reel():
    scenario = get_scenario("fight_hallway")

    assert scenario.title == "Агрессия: дополнительный пример"
    assert scenario.include_in_reel is False


def test_manifest_scenarios_allow_multiple_examples_without_hardcoding():
    manifest = {
        "clips": [
            {
                "id": "fire_01",
                "title": "Дым / огонь — пример 1",
                "category": "fire_smoke",
                "include_in_reel": True,
            },
            {
                "id": "fire_02",
                "title": "Дым / огонь — пример 2",
                "category": "fire_smoke",
                "include_in_reel": True,
            },
            {
                "id": "zone_old",
                "title": "Запретная зона",
                "category": "zone",
                "include_in_reel": False,
            },
        ]
    }

    scenarios = iter_manifest_scenarios(manifest)

    assert [scenario.id for scenario in scenarios] == ["fire_01", "fire_02"]
    assert [scenario.title for scenario in scenarios] == [
        "Дым / огонь — пример 1",
        "Дым / огонь — пример 2",
    ]
    assert all(scenario.short_label == "Дым / огонь" for scenario in scenarios)


def test_summary_can_use_manifest_scenario_metadata(tmp_path: Path):
    video = tmp_path / "fire_02_annotated.mp4"
    video.write_bytes(b"video")
    log = tmp_path / "fire_02_annotated.json"
    log.write_text('{"incidents": [], "total_frames": 50, "fps": 25.0}')
    scenario = DemoScenario("fire_02", "Дым / огонь — пример 2", "Дым / огонь", "Кухня")

    summary = build_scenario_summary("fire_02", video, log, scenario=scenario)

    assert summary["title"] == "Дым / огонь — пример 2"
