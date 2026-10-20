import json
from pathlib import Path

from typer.testing import CliRunner

from mcpscan.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, app

FIXTURES = Path(__file__).parent.parent / "fixtures" / "metadata"
runner = CliRunner()


def test_clean_scan_exits_zero() -> None:
    result = runner.invoke(app, ["scan", str(FIXTURES / "benign-weather" / "snapshots.json")])
    assert result.exit_code == EXIT_OK, result.output
    assert "no findings" in result.output


def test_findings_exit_one_and_json_is_valid() -> None:
    target = FIXTURES / "unicode-tag-smuggling" / "snapshots.json"
    result = runner.invoke(app, ["scan", str(target), "--format", "json"])
    assert result.exit_code == EXIT_FINDINGS, result.output
    report = json.loads(result.output)
    assert report["findings"][0]["rule_id"] == "MCP-TP-001"
    assert report["findings"][0]["severity"] == "critical"


def test_fail_on_threshold() -> None:
    target = FIXTURES / "zero-width-in-schema" / "snapshots.json"  # medium only
    assert runner.invoke(app, ["scan", str(target)]).exit_code == EXIT_OK
    assert runner.invoke(app, ["scan", str(target), "--fail-on", "medium"]).exit_code == (
        EXIT_FINDINGS
    )


def test_terminal_report_reveals_hidden_characters() -> None:
    target = FIXTURES / "bidi-override" / "snapshots.json"
    result = runner.invoke(app, ["scan", str(target)])
    assert "⟨U+202E⟩" in result.output
    assert "\u202e" not in result.output


def test_invalid_snapshot_exits_two(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text('{"id": "x"}', encoding="utf-8")
    assert runner.invoke(app, ["scan", str(bad)]).exit_code == EXIT_ERROR


def test_inspect_and_rules() -> None:
    target = FIXTURES / "unicode-tag-smuggling" / "snapshots.json"
    assert "⟨U+E0049⟩" in runner.invoke(app, ["inspect", str(target)]).output
    assert "MCP-TP-001" in runner.invoke(app, ["rules"]).output


def test_planned_commands_exit_two() -> None:
    result = runner.invoke(app, ["lock"])
    assert result.exit_code == EXIT_ERROR
