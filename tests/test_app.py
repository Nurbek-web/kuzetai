from protector import app as app_module


def test_launch_uses_gradio6_supported_kwargs(monkeypatch):
    calls = {}

    class FakeBlocks:
        def launch(self, *, server_port, share, css, theme, footer_links):
            calls["server_port"] = server_port
            calls["share"] = share
            calls["css"] = css
            calls["theme"] = theme
            calls["footer_links"] = footer_links

    monkeypatch.setattr(app_module, "create_app", lambda: FakeBlocks())

    app_module.launch(port=9876)

    assert calls["server_port"] == 9876
    assert calls["share"] is False
    assert ".header-bar" in calls["css"]
    assert calls["theme"] is not None
    assert calls["footer_links"] == []
