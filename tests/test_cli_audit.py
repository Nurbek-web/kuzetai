from pathlib import Path

import cli


def test_cmd_audit_reel_writes_report(monkeypatch, tmp_path: Path):
    calls = {}
    manifest_path = tmp_path / "manifest.yaml"
    manifest_path.write_text("clips: []")
    annotated_dir = tmp_path / "annotated"
    out_path = tmp_path / "audit.json"

    def fake_audit_manifest_logs(manifest, annotated):
        calls["manifest"] = manifest
        calls["annotated"] = annotated
        return [type("Result", (), {"status": "pass"})()]

    def fake_write_audit_report(results, out):
        calls["results"] = results
        calls["out"] = out

    def fake_summarize_results(results):
        calls["summary_results"] = results
        return {"passed": 1, "failed": 0, "missing_expected": 0, "false_alarm": 0}

    monkeypatch.setattr(cli, "audit_manifest_logs", fake_audit_manifest_logs, raising=False)
    monkeypatch.setattr(cli, "write_audit_report", fake_write_audit_report, raising=False)
    monkeypatch.setattr(cli, "summarize_results", fake_summarize_results, raising=False)

    args = type(
        "Args",
        (),
        {
            "manifest": str(manifest_path),
            "annotated_dir": str(annotated_dir),
            "out": str(out_path),
        },
    )()

    cli.cmd_audit_reel(args)

    assert calls["manifest"] == {"clips": []}
    assert calls["annotated"] == annotated_dir
    assert len(calls["results"]) == 1
    assert calls["out"] == out_path
