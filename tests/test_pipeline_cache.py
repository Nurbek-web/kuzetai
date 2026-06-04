from pathlib import Path

from protector import pipeline


def test_cache_roots_are_unique_within_same_second(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(pipeline, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(pipeline.time, "time", lambda: 123.0)

    first = pipeline._make_cache_root()
    second = pipeline._make_cache_root()

    assert first != second
    assert first.parent == tmp_path
    assert second.parent == tmp_path
