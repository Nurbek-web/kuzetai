from protector import fire_smoke


def test_default_fire_backend_prefers_local_fire_smoke_model(monkeypatch):
    calls = {}

    class FakePath:
        def exists(self):
            return True

        def __str__(self):
            return "/tmp/fire.pt"

    class FakeDetector:
        def __init__(self, model_path, class_names):
            calls["model_path"] = model_path
            calls["class_names"] = class_names

        def release(self):
            pass

    monkeypatch.setattr(fire_smoke, "LOCAL_FIRE_MODEL_PATH", FakePath())
    monkeypatch.setattr(fire_smoke, "HfYoloFireDetector", FakeDetector)

    detector = fire_smoke.make_fire_smoke_detector("keremberke")

    assert isinstance(detector, FakeDetector)
    assert calls == {"model_path": "/tmp/fire.pt", "class_names": ["fire", "smoke"]}
