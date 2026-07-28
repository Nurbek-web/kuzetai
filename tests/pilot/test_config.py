from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import ValidationError

from protector.pilot import config as pilot_config
from protector.pilot.config import PilotSecrets, SiteConfig, load_site_config


def _feed(number: int) -> dict[str, object]:
    return {
        "camera_id": f"camera-{number:02d}",
        "rtsp_url": {"environment": f"PILOT_CAMERA_{number:02d}_RTSP_URL"},
        "codec": "h264",
        "resolution": {"width": 1920, "height": 1080},
        "bitrate_kbps": 2_000,
        "analytics_hz": {"person": 10.0, "fire_smoke": 1.0, "weapon": 1.0},
    }


def _site_payload() -> dict[str, object]:
    return {
        "ready_to_start": {
            "feeds": [_feed(number) for number in range(1, 21)],
            "ntp_source": "ntp.customer.example",
            "camera_map": "customer-approved-map-v1",
            "site_access": "approved site-access record",
            "compute": "NVIDIA L4 pilot node",
            "notification_channel": "customer-selected Telegram connector",
            "model_rights_decisions": "model-register-v1",
        },
        "storage": {
            "country_code": "KZ",
            "endpoint": "https://object-storage.customer.example",
            "bucket": "kuzet-pilot-evidence",
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


def test_site_requires_exactly_twenty_unique_camera_ids():
    payload = _site_payload()
    site = SiteConfig.model_validate(payload)

    assert len(site.ready_to_start.feeds) == 20
    assert {feed.camera_id for feed in site.ready_to_start.feeds} == {
        f"camera-{number:02d}" for number in range(1, 21)
    }

    payload["ready_to_start"]["feeds"] = payload["ready_to_start"]["feeds"][:-1]
    with pytest.raises(ValidationError):
        SiteConfig.model_validate(payload)

    duplicate = _site_payload()
    duplicate["ready_to_start"]["feeds"][19]["camera_id"] = "camera-01"
    with pytest.raises(ValidationError):
        SiteConfig.model_validate(duplicate)


@pytest.mark.parametrize("codec", ["h264", "h265"])
def test_site_allows_only_h264_and_h265_feeds(codec: str):
    payload = _site_payload()
    payload["ready_to_start"]["feeds"][0]["codec"] = codec

    assert SiteConfig.model_validate(payload).ready_to_start.feeds[0].codec == codec


def test_site_rejects_unsupported_codec_and_nonpositive_bitrate():
    unsupported = _site_payload()
    unsupported["ready_to_start"]["feeds"][0]["codec"] = "av1"
    with pytest.raises(ValidationError):
        SiteConfig.model_validate(unsupported)

    no_bitrate = _site_payload()
    no_bitrate["ready_to_start"]["feeds"][0]["bitrate_kbps"] = 0
    with pytest.raises(ValidationError):
        SiteConfig.model_validate(no_bitrate)


def test_camera_analytics_requires_person_and_bounds_every_frequency():
    disabled_optional_module = _site_payload()
    disabled_optional_module["ready_to_start"]["feeds"][0]["analytics_hz"] = {
        "person": 10.0,
        "weapon": 0.0,
    }
    assert (
        SiteConfig.model_validate(disabled_optional_module)
        .ready_to_start.feeds[0]
        .analytics_hz["weapon"]
        == 0.0
    )

    missing_person = deepcopy(disabled_optional_module)
    missing_person["ready_to_start"]["feeds"][0]["analytics_hz"] = {"weapon": 1.0}
    with pytest.raises(ValidationError):
        SiteConfig.model_validate(missing_person)

    over_camera_rate = deepcopy(disabled_optional_module)
    over_camera_rate["ready_to_start"]["feeds"][0]["analytics_hz"]["person"] = 30.1
    with pytest.raises(ValidationError):
        SiteConfig.model_validate(over_camera_rate)


def test_site_requires_kazakhstan_https_storage_and_explicit_bounded_queues():
    payload = _site_payload()
    site = SiteConfig.model_validate(payload)
    assert site.storage.country_code == "KZ"
    assert str(site.storage.endpoint) == "https://object-storage.customer.example/"

    wrong_country = _site_payload()
    wrong_country["storage"]["country_code"] = "US"
    with pytest.raises(ValidationError):
        SiteConfig.model_validate(wrong_country)

    insecure_endpoint = _site_payload()
    insecure_endpoint["storage"]["endpoint"] = "http://object-storage.customer.example"
    with pytest.raises(ValidationError):
        SiteConfig.model_validate(insecure_endpoint)

    missing_queue = _site_payload()
    del missing_queue["queues"]["verifier"]
    with pytest.raises(ValidationError):
        SiteConfig.model_validate(missing_queue)

    unbounded_queue = _site_payload()
    unbounded_queue["queues"]["events"] = 10_001
    with pytest.raises(ValidationError):
        SiteConfig.model_validate(unbounded_queue)


def test_storage_keeps_continuous_video_in_customer_nvr_and_bounds_retention():
    site = SiteConfig.model_validate(_site_payload())
    retention = site.storage.retention
    assert retention.continuous_video_owner == "customer_nvr"
    assert retention.continuous_video_storage_enabled is False
    assert retention.encoded_ring_buffer_seconds == 15
    assert retention.encoded_ring_max_camera_bytes > 0
    assert retention.encoded_ring_max_spool_bytes >= retention.encoded_ring_max_camera_bytes

    wrong_owner = _site_payload()
    wrong_owner["storage"]["retention"]["continuous_video_owner"] = "kuzet"
    with pytest.raises(ValidationError):
        SiteConfig.model_validate(wrong_owner)

    continuous_storage = _site_payload()
    continuous_storage["storage"]["retention"]["continuous_video_storage_enabled"] = True
    with pytest.raises(ValidationError):
        SiteConfig.model_validate(continuous_storage)

    unbounded_evidence = _site_payload()
    unbounded_evidence["storage"]["retention"]["evidence_retention_days"] = 91
    with pytest.raises(ValidationError):
        SiteConfig.model_validate(unbounded_evidence)

    unbounded_metadata = _site_payload()
    unbounded_metadata["storage"]["retention"]["metadata_retention_days"] = 366
    with pytest.raises(ValidationError):
        SiteConfig.model_validate(unbounded_metadata)

    zero_disk_bound = _site_payload()
    zero_disk_bound["storage"]["retention"]["encoded_ring_max_camera_bytes"] = 0
    with pytest.raises(ValidationError):
        SiteConfig.model_validate(zero_disk_bound)

    inverted_disk_bound = _site_payload()
    inverted_disk_bound["storage"]["retention"]["encoded_ring_max_camera_bytes"] = 2_000
    inverted_disk_bound["storage"]["retention"]["encoded_ring_max_spool_bytes"] = 1_000
    with pytest.raises(ValidationError):
        SiteConfig.model_validate(inverted_disk_bound)


@pytest.mark.parametrize(
    "field",
    [
        "ntp_source",
        "camera_map",
        "site_access",
        "compute",
        "notification_channel",
        "model_rights_decisions",
    ],
)
def test_ready_to_start_requires_every_named_nonempty_field(field: str):
    payload = _site_payload()
    payload["ready_to_start"][field] = ""

    with pytest.raises(ValidationError):
        SiteConfig.model_validate(payload)


def test_site_settings_are_immutable():
    site = SiteConfig.model_validate(_site_payload())

    with pytest.raises(ValidationError):
        site.queues.decode = 128


def test_site_settings_freeze_nested_feeds_and_analytics():
    site = SiteConfig.model_validate(_site_payload())

    with pytest.raises(AttributeError):
        site.ready_to_start.feeds.pop()
    with pytest.raises(TypeError):
        site.ready_to_start.feeds[0].analytics_hz["person"] = 1.0


def test_immutable_settings_serialize_to_json_compatible_data():
    site = SiteConfig.model_validate(_site_payload())

    serialized = site.model_dump(mode="json")

    assert serialized["ready_to_start"]["feeds"][0]["analytics_hz"] == {
        "person": 10.0,
        "fire_smoke": 1.0,
        "weapon": 1.0,
    }


def test_secrets_load_only_from_environment_or_docker_secret_files(monkeypatch, tmp_path: Path):
    for name in PilotSecrets.required_names():
        monkeypatch.setenv(f"PILOT_{name.upper()}", f"env-{name}")

    environment = PilotSecrets.from_environment()
    assert environment.database_url.get_secret_value() == "env-database_url"
    assert environment.totp_encryption_key.get_secret_value() == "env-totp_encryption_key"

    for name in PilotSecrets.required_names():
        monkeypatch.delenv(f"PILOT_{name.upper()}")
        (tmp_path / name).write_text(f"file-{name}", encoding="utf-8")

    monkeypatch.setattr(pilot_config, "DOCKER_SECRETS_DIR", tmp_path, raising=False)
    docker_secrets = PilotSecrets.from_environment()
    assert docker_secrets.session_secret.get_secret_value() == "file-session_secret"

    with pytest.raises(TypeError):
        PilotSecrets.from_environment(secrets_dir=tmp_path)


def test_yaml_rejects_committed_secret_values(tmp_path: Path):
    config_path = tmp_path / "site.yaml"
    config_path.write_text(
        """
ready_to_start:
  feeds: []
  ntp_source: ntp.customer.example
  camera_map: map
  site_access: access
  compute: compute
  notification_channel: telegram
  model_rights_decisions: model-register
storage:
  country_code: KZ
  endpoint: https://object-storage.customer.example
  bucket: evidence
  secret_access_key: committed-secret
queues:
  decode: 1
  analytics: 1
  verifier: 1
  events: 1
""",
        encoding="utf-8",
    )

    with pytest.raises(ValidationError):
        load_site_config(config_path)


def test_example_template_is_a_valid_nonsecret_site_configuration():
    config_path = Path(__file__).parents[2] / "configs" / "pilot.example.yaml"

    site = load_site_config(config_path)

    assert len(site.ready_to_start.feeds) == 20
