from pathlib import Path

import numpy as np

from protector.config import BRAND_NAME
from protector.overlay import OverlayRenderer, module_label


def test_brand_name_is_kuzet_ai():
    assert BRAND_NAME == "Kuzet AI"


def test_module_labels_are_investor_facing_russian():
    assert module_label("violence") == "Агрессия"
    assert module_label("fire_smoke") == "Дым / огонь"
    assert module_label("zone") == "Запретная зона"


def test_overlay_draws_without_logo_asset(monkeypatch):
    monkeypatch.setattr("protector.overlay.LOGO_PATH", Path("/tmp/missing-kuzet-logo.png"))
    frame = np.zeros((120, 220, 3), dtype=np.uint8)
    renderer = OverlayRenderer(220, 120, 30.0)

    renderer._draw_logo(frame)

    assert int(frame.sum()) > 0
