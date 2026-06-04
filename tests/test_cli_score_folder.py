from pathlib import Path

import cli


def test_cmd_score_folder_renders_videos_and_writes_audit(monkeypatch, tmp_path: Path):
    input_dir = tmp_path / "candidates"
    input_dir.mkdir()
    (input_dir / "a.mp4").write_bytes(b"video")
    (input_dir / "b.mov").write_bytes(b"video")
    out_dir = tmp_path / "out"
    calls = {"run_file": []}

    def fake_run_file(input_path, output_path, zones, enabled_modules):
        calls["run_file"].append((input_path, output_path, zones, enabled_modules))
        Path(output_path).with_suffix(".json").write_text('{"incidents": []}')
        return []

    def fake_audit_log(clip_id, log_path, expected_modules):
        calls.setdefault("audit", []).append((clip_id, log_path, expected_modules))
        return type("Result", (), {"status": "pass", "as_dict": lambda self: {}})()

    def fake_write_audit_report(results, out):
        calls["report"] = (results, out)

    def fake_summarize_results(results):
        calls["summary_results"] = results
        return {"passed": 2, "failed": 0, "missing_expected": 0, "false_alarm": 0}

    monkeypatch.setattr(cli, "run_file", fake_run_file, raising=False)
    monkeypatch.setattr(cli, "audit_log", fake_audit_log, raising=False)
    monkeypatch.setattr(cli, "write_audit_report", fake_write_audit_report, raising=False)
    monkeypatch.setattr(cli, "summarize_results", fake_summarize_results, raising=False)

    args = type(
        "Args",
        (),
        {
            "input_dir": str(input_dir),
            "out": str(out_dir),
            "modules": "fire_smoke",
            "expected": "fire_smoke",
            "force": False,
        },
    )()

    cli.cmd_score_folder(args)

    assert len(calls["run_file"]) == 2
    assert calls["run_file"][0][3] == ["fire_smoke"]
    assert calls["audit"][0][2] == ["fire_smoke"]
    assert calls["report"][1] == out_dir / "audit_report.json"
