"""Command-line interface.

Exit codes: 0 = no findings at or above --fail-on, 1 = findings at or above --fail-on,
2 = scanner error (bad input, a rule crashed, command not implemented yet).
"""

from __future__ import annotations

import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated, NoReturn

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table
from rich.text import Text

from mcpscan import __version__
from mcpscan.core.io import load_snapshots
from mcpscan.core.models import ServerSnapshot, Severity
from mcpscan.core.pipeline import scan as run_scan
from mcpscan.core.text import iter_text_fields, reveal
from mcpscan.report import json_report, terminal
from mcpscan.rules import load_rules

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2

app = typer.Typer(
    name="mcpscan",
    help="Security scanner for MCP (Model Context Protocol) servers.",
    no_args_is_help=True,
    add_completion=False,
)
out = Console()
err = Console(stderr=True)


class OutputFormat(StrEnum):
    TTY = "tty"
    JSON = "json"


SnapshotArg = Annotated[
    Path,
    typer.Argument(
        exists=True, dir_okay=False, readable=True,
        help="Snapshot JSON file (one ServerSnapshot or a list). Config files, packages and URLs "
        "come in Phase 1.",
    ),
]  # fmt: skip


def _fail(message: str) -> NoReturn:
    err.print(Text(f"error: {message}", style="red"))
    raise typer.Exit(EXIT_ERROR)


def _load(path: Path) -> list[ServerSnapshot]:
    try:
        return load_snapshots(path)
    except ValidationError as exc:
        _fail(f"{path} is not a valid snapshot file:\n{exc}")
    except ValueError as exc:  # includes json.JSONDecodeError
        _fail(f"{path} is not valid JSON: {exc}")


def _version(value: bool) -> None:
    if value:
        out.print(f"mcpscan {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool, typer.Option("--version", callback=_version, is_eager=True, help="Show version.")
    ] = False,
) -> None:
    """Security scanner for MCP (Model Context Protocol) servers."""


@app.command()
def scan(
    target: SnapshotArg,
    fmt: Annotated[OutputFormat, typer.Option("--format", "-f", help="Output format.")] = (
        OutputFormat.TTY
    ),
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write the report to a file.")
    ] = None,
    fail_on: Annotated[
        Severity, typer.Option(help="Exit 1 if any finding is at or above this severity.")
    ] = Severity.HIGH,
    plugins: Annotated[bool, typer.Option(help="Load third-party rule packs.")] = True,
) -> None:
    """Scan MCP servers for security issues."""
    result = run_scan(_load(target), load_rules(plugins=plugins))

    if fmt is OutputFormat.JSON:
        report = json_report.render(result)
        if output:
            output.write_text(report, encoding="utf-8")
        else:
            sys.stdout.write(report)
    elif output:
        with output.open("w", encoding="utf-8") as fh:
            terminal.render(result, Console(file=fh, no_color=True, width=120))
    else:
        terminal.render(result, out)

    if result.errors:
        raise typer.Exit(EXIT_ERROR)
    worst = result.max_severity()
    raise typer.Exit(EXIT_FINDINGS if worst and worst.rank >= fail_on.rank else EXIT_OK)


@app.command("inspect")
def inspect_cmd(target: SnapshotArg) -> None:
    """Show every piece of text the model will read, with hidden characters revealed."""
    for snapshot in _load(target):
        out.rule(Text(reveal(f"{snapshot.name}  ({snapshot.origin.kind}: {snapshot.origin.ref})")))
        for tf in iter_text_fields(snapshot):
            shown = reveal(tf.text)
            out.print(Text(tf.location.json_pointer or "", style="dim"))
            out.print(Text(f"  {shown}", style="bold yellow" if shown != tf.text else ""))


@app.command("rules")
def list_rules(
    plugins: Annotated[bool, typer.Option(help="Include third-party rule packs.")] = True,
) -> None:
    """List the available detection rules."""
    table = Table("ID", "Severity", "Category", "Title")
    for rule in load_rules(plugins=plugins):
        sev = rule.default_severity
        table.add_row(
            rule.id, Text(sev.value, style=terminal.SEVERITY_STYLE[sev]), rule.category.value,
            rule.title,
        )  # fmt: skip
    out.print(table)


def _planned(command: str, phase: str) -> NoReturn:
    _fail(f"`mcpscan {command}` is planned for {phase} (see docs/ARCHITECTURE.md §10).")


@app.command()
def lock() -> None:
    """Pin the current tool definitions to mcp-lock.json."""
    _planned("lock", "Phase 1")


@app.command()
def verify() -> None:
    """Check tool definitions against mcp-lock.json (rug-pull detection)."""
    _planned("verify", "Phase 1")


@app.command()
def bench() -> None:
    """Score a classifier or LLM against the fixture corpus."""
    _planned("bench", "Phase 2")


@app.command()
def serve() -> None:
    """Run mcpscan itself as an MCP server."""
    _planned("serve", "Phase 5")


@app.command()
def proxy() -> None:
    """Run as a runtime guard between an MCP client and server."""
    _planned("proxy", "Phase 5")
