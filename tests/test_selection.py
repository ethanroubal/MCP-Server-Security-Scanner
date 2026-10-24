"""Selection is exact, validated, and applied before any external work."""

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from mcpiranha.cli import EXIT_ERROR, app
from mcpiranha.core.models import Origin, ServerSnapshot
from mcpiranha.targets import TargetError, Targets, select
from tests.helpers import snapshot_with_description

runner = CliRunner()


def _snapshots() -> list[ServerSnapshot]:
    base = snapshot_with_description("Adds numbers.")
    return [
        base.model_copy(
            update={
                "id": f"{client}:{name}",
                "name": name,
                "origin": Origin(kind="config", client=client, ref=client),
            }
        )
        for client, name in (("cursor", "math"), ("claude-desktop", "math"), ("cursor", "files"))
    ]


def test_select_names_ids_and_clients() -> None:
    targets = Targets(_snapshots())
    assert len(select(targets, servers=["math"]).snapshots) == 2
    assert [s.id for s in select(targets, servers=["cursor:math"]).snapshots] == ["cursor:math"]
    assert [s.id for s in select(targets, servers=["math"], clients=["cursor"]).snapshots] == [
        "cursor:math"
    ]
    assert len(select(targets, servers=["math", "files"], clients=["cursor"]).snapshots) == 2
    with pytest.raises(TargetError, match="no server matches"):
        select(targets, servers=["math", "typo"])
    with pytest.raises(TargetError, match="no client matches"):
        select(targets, clients=["cursor", "typo"])
    with pytest.raises(TargetError, match="no server matches"):
        select(targets, servers=["cursor:math"], clients=["claude-desktop"])
    assert len(targets.snapshots) == 3  # do not mutate discovery results


def test_selection_precedes_connection_supply_and_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "config.json"
    target.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "chosen": {"command": "npx", "args": ["chosen@1"]},
                    "unrelated": {"command": "npx", "args": ["unrelated@1"]},
                }
            }
        )
    )
    visited: list[tuple[str, list[str]]] = []

    async def connect(
        snapshots: list[ServerSnapshot], *args: Any, **kwargs: Any
    ) -> tuple[list[ServerSnapshot], list[str]]:
        visited.append(("connect", [s.name for s in snapshots]))
        return [s.model_copy(update={"tools_listed": True}) for s in snapshots], []

    async def enrich(
        snapshots: list[ServerSnapshot], *args: Any, **kwargs: Any
    ) -> tuple[list[ServerSnapshot], list[str]]:
        visited.append(("supply", [s.name for s in snapshots]))
        return snapshots, []

    async def source(
        snapshots: list[ServerSnapshot], *args: Any, **kwargs: Any
    ) -> tuple[list[ServerSnapshot], list[str]]:
        visited.append(("source", [s.name for s in snapshots]))
        return snapshots, []

    monkeypatch.setenv("MCPIRANHA_OFFLINE", "0")
    monkeypatch.setattr("mcpiranha.cli.connect_all", connect)
    monkeypatch.setattr("mcpiranha.cli.supply.enrich", enrich)
    monkeypatch.setattr("mcpiranha.cli.source.collect", source)
    result = runner.invoke(
        app,
        [
            "scan",
            str(target),
            "--server",
            "chosen",
            "--connect",
            "--invoke",
            "echo",
            "--no-lock",
            "-f",
            "json",
        ],
    )
    assert result.exit_code in (0, 1), result.output
    assert visited == [("connect", ["chosen"]), ("supply", ["chosen"]), ("source", ["chosen"])]
    assert [s["name"] for s in json.loads(result.stdout)["servers"]] == ["chosen"]
    visited.clear()
    typo = runner.invoke(
        app,
        ["scan", str(target), "--server", "chosen", "--server", "typo", "--connect", "-f", "json"],
    )
    assert typo.exit_code == EXIT_ERROR
    assert "no server matches" in typo.output
    assert visited == []


def test_selected_snapshot_cli_and_lock_verification(tmp_path: Path) -> None:
    target = tmp_path / "snapshots.json"
    target.write_text(json.dumps([s.model_dump(mode="json") for s in _snapshots()]))
    result = runner.invoke(
        app,
        ["scan", str(target), "--server", "math", "--client", "cursor", "--no-lock", "-f", "json"],
    )
    assert result.exit_code == 0, result.output
    assert [s["id"] for s in json.loads(result.stdout)["servers"]] == ["cursor:math"]
    lock = tmp_path / "lock.json"
    assert runner.invoke(app, ["lock", str(target), "-o", str(lock)]).exit_code == 0
    verified = runner.invoke(
        app,
        [
            "verify",
            str(target),
            "--server",
            "math",
            "--client",
            "cursor",
            "--lockfile",
            str(lock),
            "-f",
            "json",
        ],
    )
    assert verified.exit_code == 0, verified.output
    assert "Removed since lock" not in verified.stderr
    for command in ("inspect", "flows"):
        selected = runner.invoke(app, [command, str(target), "--server", "cursor:math"])
        assert selected.exit_code == 0, selected.output
        assert "files" not in selected.output


def test_saved_coverage_is_labelled_and_offline_gaps_explained(tmp_path: Path) -> None:
    from mcpiranha.core.models import CoverageCheck, Launch

    snapshot = _snapshots()[0].model_copy(
        update={
            "launch": Launch(transport="stdio", command="npx", args=["pkg@1"]),
            "coverage": {
                "dynamic": CoverageCheck(status="completed", reason="Bounded trace completed.")
            },
        }
    )
    target = tmp_path / "snapshot.json"
    target.write_text(snapshot.model_dump_json())
    result = runner.invoke(app, ["scan", str(target), "--offline", "--no-lock", "-f", "json"])
    assert result.exit_code in (0, 1), result.output
    coverage = json.loads(result.stdout)["servers"][0]["coverage"]
    assert coverage["dynamic"]["status"] == "completed"
    assert coverage["dynamic"]["reason"].startswith("Saved evidence:")
    assert coverage["package"]["status"] == "skipped"
    assert "Offline" in coverage["package"]["reason"]
    assert "Offline" in coverage["dependencies"]["reason"]
    assert "Offline" in coverage["source"]["reason"]
