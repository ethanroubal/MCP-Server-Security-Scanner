"""Static targets must inspect code without launching, installing, or importing it."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from mcpiranha.cli import app
from mcpiranha.core.models import PackageMeta, ServerSnapshot
from mcpiranha.targets import resolve

runner = CliRunner()


def _forbid(*args: Any, **kwargs: Any) -> Any:
    raise AssertionError("static inspection must not execute a process or connect to a server")


@pytest.mark.parametrize(
    "registry,spec", [("npm", "npm:fixture@1.0.0"), ("pypi", "pypi:fixture==1.0.0")]
)
def test_static_package_archives_are_inspected_without_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, registry: str, spec: str
) -> None:
    marker = tmp_path / "MUST_NOT_EXIST"
    code = f'from pathlib import Path\nPath({str(marker)!r}).write_text("executed")\n'
    code += "import json, os\nsecrets = json.dumps(dict(os.environ))\n"
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w:gz") as tar:
        data = code.encode()
        info = tarfile.TarInfo("package/server.py")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    payload = archive.getvalue()
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()

    async def enrich(
        snapshots: list[ServerSnapshot], **kwargs: Any
    ) -> tuple[list[ServerSnapshot], list[str]]:
        package = PackageMeta.model_validate(
            {
                "registry": registry,
                "name": "fixture",
                "version": "1.0.0",
                "archive_url": "https://example.invalid/fixture.tgz",
                "archive_hash": digest,
                "install_scripts": [f"python -c {code!r}"],
            }
        )
        return [s.model_copy(update={"package": package}) for s in snapshots], []

    async def download(client: Any, url: str, expected: str) -> bytes:
        assert expected == digest
        return payload

    monkeypatch.setenv("MCPIRANHA_OFFLINE", "0")
    monkeypatch.setattr("mcpiranha.cli.supply.enrich", enrich)
    monkeypatch.setattr("mcpiranha.source._download", download)
    monkeypatch.setattr("mcpiranha.cli.connect_all", _forbid)
    monkeypatch.setattr("anyio.run_process", _forbid)
    monkeypatch.setattr("subprocess.Popen", _forbid)
    result = runner.invoke(app, ["scan", spec, "--no-lock", "-f", "json"])
    assert result.exit_code == 1, result.output
    report = json.loads(result.stdout)
    assert report["errors"] == []
    assert "MCP-SRC-002" in {f["rule_id"] for f in report["findings"]}
    coverage = report["servers"][0]["coverage"]
    assert coverage["source"]["status"] == "completed"
    assert coverage["tools"]["status"] == "skipped"
    assert coverage["dynamic"]["status"] == "skipped"
    assert not marker.exists()


@pytest.mark.parametrize("style", ["directory", "explicit-path", "file"])
def test_local_source_never_executes_and_reports_parser_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, style: str
) -> None:
    marker = tmp_path / "MUST_NOT_EXIST"
    source = tmp_path / "server.py"
    source.write_text(f"from pathlib import Path\nPath({str(marker)!r}).touch()\ndef invalid(:\n")
    target = str(source) if style == "file" else str(tmp_path)
    if style == "explicit-path":
        target = "path:" + target
    monkeypatch.setattr("anyio.run_process", _forbid)
    monkeypatch.setattr("subprocess.Popen", _forbid)
    monkeypatch.setattr("mcpiranha.cli.connect_all", _forbid)
    result = runner.invoke(
        app,
        ["scan", target, "--offline", "--no-lock", "-f", "json", "--require-coverage", "source"],
    )
    assert result.exit_code == 2, result.output
    report = json.loads(result.stdout)
    assert report["servers"][0]["coverage"]["source"]["status"] == "partial"
    assert "Python parse failed" in report["servers"][0]["coverage"]["source"]["reason"]
    assert not marker.exists()


def test_config_discovery_is_preserved_and_path_prefix_overrides_it(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text('{"mcpServers":{"configured":{"command":"node"}}}')
    assert resolve(str(tmp_path), tmp_path).snapshots[0].name == "configured"
    assert resolve("path:" + str(tmp_path), tmp_path).snapshots[0].launch is None


def test_source_exclusions_and_no_symlink_escape(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    (root / "good.py").write_text("value = 1\n")
    ignored = root / "node_modules"
    ignored.mkdir()
    (ignored / "bad.py").write_text("def invalid(:\n")
    external = tmp_path / "external.py"
    external.write_text("def invalid(:\n")
    (root / "linked.py").symlink_to(external)
    result = runner.invoke(
        app,
        ["scan", str(root), "--offline", "--no-lock", "-f", "json", "--require-coverage", "source"],
    )
    assert result.exit_code == 0, result.output
    coverage = json.loads(result.stdout)["servers"][0]["coverage"]["source"]
    assert coverage["status"] == "completed" and coverage["count"] == 1


def test_static_source_rejects_connection_request(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", "path:" + str(tmp_path), "--connect"])
    assert result.exit_code == 2
    assert "static inspection only" in result.output


def test_direct_source_finding_has_real_file_location(tmp_path: Path) -> None:
    source = tmp_path / "server.py"
    source.write_text("import os,json\nsecrets=json.dumps(dict(os.environ))\n")
    result = runner.invoke(app, ["scan", str(source), "--offline", "--no-lock", "-f", "json"])
    assert result.exit_code == 1, result.output
    [finding] = json.loads(result.stdout)["findings"]
    assert Path(finding["location"]["file"]).resolve() == source.resolve()


def test_source_only_targets_cannot_create_empty_lockfiles(tmp_path: Path) -> None:
    lockfile = tmp_path / "lock.json"
    result = runner.invoke(app, ["lock", "path:" + str(tmp_path), "-o", str(lockfile)])
    assert result.exit_code == 2
    assert not lockfile.exists()


def test_saved_source_replays_without_original_checkout(tmp_path: Path) -> None:
    source = tmp_path / "server.py"
    source.write_text("value = 1\n")
    captures = tmp_path / "captures"
    first = runner.invoke(
        app, ["scan", str(source), "--offline", "--no-lock", "--save-snapshots", str(captures)]
    )
    assert first.exit_code == 0, first.output
    source.unlink()
    [saved] = list(captures.glob("*.json"))
    replay = runner.invoke(
        app,
        [
            "scan",
            str(saved),
            "--offline",
            "--no-lock",
            "--require-coverage",
            "source",
            "-f",
            "json",
        ],
    )
    assert replay.exit_code == 0, replay.output
    coverage = json.loads(replay.stdout)["servers"][0]["coverage"]["source"]
    assert coverage["status"] == "completed"
    assert coverage["reason"].startswith("Saved evidence:")


def test_oversized_local_files_are_bounded_and_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("mcpiranha.source.MAX_FILE", 32)
    source = tmp_path / "large.py"
    source.write_bytes(b"x" * 1024)
    result = runner.invoke(
        app,
        [
            "scan",
            str(source),
            "--offline",
            "--no-lock",
            "--require-coverage",
            "source",
            "-f",
            "json",
        ],
    )
    assert result.exit_code == 2, result.output
    coverage = json.loads(result.stdout)["servers"][0]["coverage"]["source"]
    assert coverage["status"] == "partial" and "larger than" in coverage["reason"]
