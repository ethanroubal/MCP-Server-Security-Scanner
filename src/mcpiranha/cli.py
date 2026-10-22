"""Command-line interface.

Exit codes: 0 = no findings at or above --fail-on, 1 = findings at or above --fail-on,
2 = scanner error (bad input, a rule crashed, command not implemented yet).
"""

from __future__ import annotations

import functools
import re
import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated, NoReturn

import anyio
import typer
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table
from rich.text import Text

from mcpiranha import __version__
from mcpiranha.acquire import ConnectOptions, connect_all
from mcpiranha.acquire.oauth import open_in_browser
from mcpiranha.core.lockfile import LOCKFILE_NAME, Lockfile, build_lockfile
from mcpiranha.core.models import CapabilityLabel, Category, ScanResult, ServerSnapshot, Severity
from mcpiranha.core.pipeline import inventories
from mcpiranha.core.pipeline import scan as run_scan
from mcpiranha.core.policy import POLICY_FILE, Policy, PolicyError
from mcpiranha.core.text import iter_text_fields, reveal
from mcpiranha.flows import inventory_capabilities
from mcpiranha.report import json_report, sarif, terminal
from mcpiranha.rules import Rule, load_rules
from mcpiranha.targets import TargetError, Targets, resolve

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2
RUG_PULL_RULE = "MCP-RP-001"

app = typer.Typer(
    name="mcpiranha",
    help="Security scanner for MCP (Model Context Protocol) servers.",
    no_args_is_help=True,
    add_completion=False,
)
out = Console()
err = Console(stderr=True)


class OutputFormat(StrEnum):
    TTY = "tty"
    JSON = "json"
    SARIF = "sarif"


class SandboxMode(StrEnum):
    DOCKER = "docker"
    NONE = "none"


TargetArg = Annotated[
    str | None,
    typer.Argument(
        help="A client config file, a project directory, or a snapshot JSON file; with --connect "
        "also npm:<pkg>, pypi:<pkg>, docker:<image> or a server URL. Omit to scan every MCP "
        "client config on this machine plus the current project.",
        show_default=False,
    ),
]
FormatOpt = Annotated[OutputFormat, typer.Option("--format", "-f", help="Output format.")]
OutputOpt = Annotated[Path | None, typer.Option("--output", "-o", help="Write the report here.")]
PluginsOpt = Annotated[bool, typer.Option(help="Load third-party rule packs.")]
ConnectOpt = Annotated[
    bool,
    typer.Option(
        "--connect",
        help="Start each server (sandboxed) or reach it, and list its tools, prompts and "
        "resources. No tool is ever called.",
    ),
]
SandboxOpt = Annotated[
    SandboxMode,
    typer.Option(
        help="How --connect runs stdio servers: 'docker' (no network, read-only, no privileges) "
        "or 'none' (directly on this machine, like your MCP client does)."
    ),
]
RealCredentialsOpt = Annotated[
    bool,
    typer.Option(
        "--real-credentials",
        help="Give servers the real env values and headers from the config (with ${VAR} "
        "expanded) instead of dummy values.",
    ),
]
TimeoutOpt = Annotated[float, typer.Option(help="Seconds to wait for each server to answer.")]
JobsOpt = Annotated[int, typer.Option(min=1, help="Servers to connect to at the same time.")]
AllowNetworkOpt = Annotated[
    bool,
    typer.Option(
        "--allow-network",
        help="Let sandboxed servers use the network while running (some fetch data at startup). "
        "They still get dummy credentials unless --real-credentials is given.",
    ),
]
AllowScriptsOpt = Annotated[
    bool,
    typer.Option(
        "--allow-install-scripts",
        help="Run npm install scripts and build PyPI source packages in the sandbox's download "
        "step. Off by default, since that runs the package's code with network access.",
    ),
]
HeaderOpt = Annotated[
    list[str] | None,
    typer.Option(
        "--header", "-H",
        help="'Name: value' header for a remote server, e.g. a bearer token. Only with a single "
        "server URL target, so it can't be sent anywhere else. Repeatable.",
        show_default=False,
    ),
]  # fmt: skip
OAuthOpt = Annotated[
    bool,
    typer.Option(
        "--oauth",
        help="Sign in to remote servers that require OAuth (opens a browser). Tokens are kept "
        "in memory for this run only.",
    ),
]
PolicyOpt = Annotated[
    Path | None,
    typer.Option(
        "--policy", help=f"Policy file with suppressions. Default: ./{POLICY_FILE} if present."
    ),
]
StrictOpt = Annotated[
    bool | None,
    typer.Option(
        "--strict/--no-strict",
        help="Exit 2 if any server couldn't be connected to, so CI never passes on a partial "
        "scan. Default: the policy's `strict`, else off.",
        show_default=False,
    ),
]


def _fail(message: str) -> NoReturn:
    err.print(Text(f"error: {message}", style="red"))
    raise typer.Exit(EXIT_ERROR)


def _warn(message: str) -> None:
    err.print(Text(f"warning: {reveal(message)}", style="yellow"))


def _progress(snapshot: ServerSnapshot, message: str) -> None:
    err.print(Text(f"  {reveal(snapshot.name)}: {message}", style="dim"), soft_wrap=True)


def _parse_headers(raw: list[str] | None) -> dict[str, str]:
    headers: dict[str, str] = {}
    for item in raw or []:
        name, sep, value = item.partition(":")
        if not sep or not name.strip():
            _fail(f"--header must look like 'Name: value', got {item!r}")
        headers[name.strip()] = value.strip()
    return headers


def _targets(
    target: str | None,
    *,
    connect: bool = False,
    sandbox: SandboxMode = SandboxMode.DOCKER,
    real_credentials: bool = False,
    timeout: float = 60.0,
    jobs: int = 4,
    header: list[str] | None = None,
    oauth: bool = False,
    allow_network: bool = False,
    allow_install_scripts: bool = False,
) -> tuple[Targets, list[str]]:
    """Resolve the target and, with --connect, list every server. Returns connection warnings."""
    try:
        targets = resolve(target, Path.cwd(), connect=connect)
    except TargetError as exc:
        _fail(str(exc))
    for warning in targets.warnings:
        _warn(warning)
    headers = _parse_headers(header)
    if (headers or oauth) and not connect:
        _fail("--header and --oauth only apply with --connect")
    if headers and not (
        len(targets.snapshots) == 1 and targets.snapshots[0].origin.kind == "remote"
    ):
        _fail("--header only works with a single server URL as the target")
    if not connect or not targets.snapshots:
        return targets, []

    if sandbox is SandboxMode.NONE:
        _warn("--sandbox none: stdio servers run directly on this machine, with your user's access")
    if real_credentials:
        _warn("--real-credentials: servers get the real secrets from your config")
    if allow_network:
        _warn("--allow-network: sandboxed servers can reach the network while running")
    if allow_install_scripts:
        _warn("--allow-install-scripts: package install code runs during download (sandboxed)")
    options = ConnectOptions(
        sandbox=sandbox.value, real_credentials=real_credentials, timeout=timeout, jobs=jobs,
        extra_headers=headers or None, oauth_open=open_in_browser if oauth else None,
        allow_network=allow_network, allow_install_scripts=allow_install_scripts,
    )  # fmt: skip
    err.print(Text(f"Connecting to {len(targets.snapshots)} server(s)...", style="dim"))
    run = functools.partial(connect_all, targets.snapshots, options, _progress)
    targets.snapshots, warnings = anyio.run(run)
    for warning in warnings:
        _warn(warning)
    return targets, warnings


def _describe_sources(targets: Targets, *, connected: bool) -> None:
    # soft_wrap: long paths stay on one line so they can be copied
    if targets.snapshot_file:
        out.print(Text(f"Snapshot file {targets.snapshot_file}", style="dim"), soft_wrap=True)
    for f in targets.config_files:
        line = f"{f.client:<15} {f.scope:<8} {f.path}  ({f.servers} server(s))"
        out.print(Text(line, style="dim"), soft_wrap=True)
    unlisted = sum(not s.tools_listed for s in targets.snapshots)
    if not targets.snapshots:
        out.print("No MCP servers found.")
    elif unlisted:
        why = "see the warnings above" if connected else "add --connect to list them"
        out.print(
            Text(
                f"Tools weren't listed for {unlisted} server(s), so their tool metadata isn't "
                f"checked ({why}).",
                style="dim",
            )
        )
    out.print()


def _load_policy(path: Path | None) -> Policy:
    path = path or Path.cwd() / POLICY_FILE
    if not path.is_file():
        if path.name != POLICY_FILE or path.parent != Path.cwd():
            _fail(f"policy file {path} not found")
        return Policy()
    try:
        return Policy.load(path)
    except PolicyError as exc:
        _fail(str(exc))


def _finish(result: ScanResult, *, strict: bool, failed: bool) -> NoReturn:
    """Exit with the right code. `failed`: findings that should fail the run."""
    if result.errors:
        raise typer.Exit(EXIT_ERROR)
    if strict and result.warnings:
        err.print(Text("error: --strict: not every server could be checked (see warnings)",
                       style="red"))  # fmt: skip
        raise typer.Exit(EXIT_ERROR)
    raise typer.Exit(EXIT_FINDINGS if failed else EXIT_OK)


def _save_snapshots(snapshots: list[ServerSnapshot], directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for snapshot in snapshots:
        name = re.sub(r"[^A-Za-z0-9._-]+", "_", snapshot.id).strip("_")[:120] or "server"
        path = directory / f"{name}.json"
        path.write_text(snapshot.model_dump_json(indent=2) + "\n", encoding="utf-8")


def _classifier_rule() -> Rule:
    from mcpiranha.classifier import ClassifierUnavailable, load
    from mcpiranha.classifier.rule import ClassifierRule

    try:
        return ClassifierRule(load(progress=lambda m: err.print(Text(m, style="dim"))))
    except ClassifierUnavailable as exc:
        _fail(str(exc))


def _load_lock(path: Path) -> Lockfile:
    try:
        return Lockfile.load(path)
    except (OSError, ValueError, ValidationError) as exc:
        _fail(f"could not read lockfile {path}: {exc}")


def _emit(result: ScanResult, rules: list[Rule], fmt: OutputFormat, output: Path | None) -> None:
    if fmt is OutputFormat.TTY:
        if output:
            with output.open("w", encoding="utf-8") as fh:
                terminal.render(result, Console(file=fh, no_color=True, width=120))
        else:
            terminal.render(result, out)
        return
    report = json_report.render(result) if fmt is OutputFormat.JSON else sarif.render(result, rules)
    if output:
        output.write_text(report, encoding="utf-8")
    else:
        sys.stdout.write(report)


def _version(value: bool) -> None:
    if value:
        out.print(f"mcpiranha {__version__}")
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
    target: TargetArg = None,
    connect: ConnectOpt = False,
    sandbox: SandboxOpt = SandboxMode.DOCKER,
    real_credentials: RealCredentialsOpt = False,
    timeout: TimeoutOpt = 60.0,
    jobs: JobsOpt = 4,
    header: HeaderOpt = None,
    oauth: OAuthOpt = False,
    allow_network: AllowNetworkOpt = False,
    allow_install_scripts: AllowScriptsOpt = False,
    fmt: FormatOpt = OutputFormat.TTY,
    output: OutputOpt = None,
    fail_on: Annotated[
        Severity | None,
        typer.Option(
            help="Exit 1 if any finding is at or above this severity. Default: the policy's "
            "`fail_on`, else high.",
            show_default=False,
        ),
    ] = None,
    policy_file: PolicyOpt = None,
    strict: StrictOpt = None,
    lockfile: Annotated[
        Path | None,
        typer.Option(help=f"Lockfile to check for changes. Default: ./{LOCKFILE_NAME} if present."),
    ] = None,
    use_lock: Annotated[bool, typer.Option("--lock/--no-lock", help="Use a lockfile.")] = True,
    save_snapshots: Annotated[
        Path | None,
        typer.Option(
            help="Write each server's snapshot (what it served; secrets masked) to this directory, "
            "so it can be rescanned offline later.",
        ),
    ] = None,
    classifier: Annotated[
        bool,
        typer.Option(
            "--classifier",
            help="Experimental: also run the local prompt-injection classifier (needs "
            "`mcpiranha[ml]`; downloads a ~740 MB model once). Its findings are low severity.",
        ),
    ] = False,
    plugins: PluginsOpt = True,
) -> None:
    """Scan MCP servers for security issues."""
    targets, warnings = _targets(
        target, connect=connect, sandbox=sandbox, real_credentials=real_credentials,
        timeout=timeout, jobs=jobs, header=header, oauth=oauth, allow_network=allow_network,
        allow_install_scripts=allow_install_scripts,
    )  # fmt: skip
    if fmt is OutputFormat.TTY and not output:
        _describe_sources(targets, connected=connect)

    lock = None
    if use_lock:
        path = lockfile or Path.cwd() / LOCKFILE_NAME
        if lockfile or path.is_file():
            lock = _load_lock(path)

    policy = _load_policy(policy_file)
    if save_snapshots:
        _save_snapshots(targets.snapshots, save_snapshots)
    rules = load_rules(plugins=plugins)
    if classifier:
        rules.append(_classifier_rule())
    result = run_scan(targets.snapshots, rules, lock=lock).model_copy(update={"warnings": warnings})
    result = policy.apply(result)
    _emit(result, rules, fmt, output)

    threshold = fail_on or policy.fail_on or Severity.HIGH
    worst = result.max_severity()
    _finish(result, strict=policy.strict if strict is None else strict,
            failed=worst is not None and worst.rank >= threshold.rank)  # fmt: skip


@app.command()
def lock(
    target: TargetArg = None,
    connect: ConnectOpt = False,
    sandbox: SandboxOpt = SandboxMode.DOCKER,
    real_credentials: RealCredentialsOpt = False,
    timeout: TimeoutOpt = 60.0,
    jobs: JobsOpt = 4,
    header: HeaderOpt = None,
    oauth: OAuthOpt = False,
    allow_network: AllowNetworkOpt = False,
    allow_install_scripts: AllowScriptsOpt = False,
    output: Annotated[Path, typer.Option("--output", "-o", help="Lockfile to write.")] = Path(
        LOCKFILE_NAME
    ),
) -> None:
    """Pin the current launch configs and tool definitions to a lockfile."""
    targets, _ = _targets(
        target, connect=connect, sandbox=sandbox, real_credentials=real_credentials,
        timeout=timeout, jobs=jobs, header=header, oauth=oauth, allow_network=allow_network,
        allow_install_scripts=allow_install_scripts,
    )  # fmt: skip
    if not targets.snapshots:
        _fail("no MCP servers found to lock")
    lockfile = build_lockfile(targets.snapshots)
    lockfile.save(output)
    with_tools = sum(1 for s in lockfile.servers.values() if s.tools is not None)
    out.print(f"Locked {len(lockfile.servers)} server(s) to {output}.")
    if with_tools < len(lockfile.servers):
        out.print(
            Text(
                f"{len(lockfile.servers) - with_tools} server(s) only have their launch config "
                "pinned; run with --connect to pin their tool definitions too.",
                style="dim",
            )
        )


@app.command()
def verify(
    target: TargetArg = None,
    connect: ConnectOpt = False,
    sandbox: SandboxOpt = SandboxMode.DOCKER,
    real_credentials: RealCredentialsOpt = False,
    timeout: TimeoutOpt = 60.0,
    jobs: JobsOpt = 4,
    header: HeaderOpt = None,
    oauth: OAuthOpt = False,
    allow_network: AllowNetworkOpt = False,
    allow_install_scripts: AllowScriptsOpt = False,
    lockfile: Annotated[Path, typer.Option(help="Lockfile to verify against.")] = Path(
        LOCKFILE_NAME
    ),
    fmt: FormatOpt = OutputFormat.TTY,
    output: OutputOpt = None,
    policy_file: PolicyOpt = None,
    strict: StrictOpt = None,
) -> None:
    """Check servers against a lockfile: exit 1 if anything changed or was added."""
    if not lockfile.is_file():
        _fail(f"{lockfile} not found; create it with `mcpiranha lock`")
    locked = _load_lock(lockfile)
    targets, warnings = _targets(
        target, connect=connect, sandbox=sandbox, real_credentials=real_credentials,
        timeout=timeout, jobs=jobs, header=header, oauth=oauth, allow_network=allow_network,
        allow_install_scripts=allow_install_scripts,
    )  # fmt: skip
    policy = _load_policy(policy_file)
    rules = [r for r in load_rules(plugins=False) if r.id == RUG_PULL_RULE]
    result = run_scan(targets.snapshots, rules, lock=locked).model_copy(
        update={"warnings": warnings}
    )
    result = policy.apply(result)
    _emit(result, rules, fmt, output)

    current = {s.id: s.name for s in targets.snapshots}
    added = sorted(name for sid, name in current.items() if sid not in locked.servers)
    removed = sorted(s.name for sid, s in locked.servers.items() if sid not in current)
    for label, names, style in (("Added since lock", added, "bold red"),
                                ("Removed since lock", removed, "yellow")):  # fmt: skip
        if names:
            err.print(Text(f"{label}: ", style=style) + Text(reveal(", ".join(names))))

    _finish(result, strict=policy.strict if strict is None else strict,
            failed=bool(result.findings or added))  # fmt: skip


@app.command("inspect")
def inspect_cmd(
    target: TargetArg = None,
    connect: ConnectOpt = False,
    sandbox: SandboxOpt = SandboxMode.DOCKER,
    real_credentials: RealCredentialsOpt = False,
    timeout: TimeoutOpt = 60.0,
    jobs: JobsOpt = 4,
    header: HeaderOpt = None,
    oauth: OAuthOpt = False,
    allow_network: AllowNetworkOpt = False,
    allow_install_scripts: AllowScriptsOpt = False,
) -> None:
    """Show every piece of text the model will read, with hidden characters revealed."""
    targets, _ = _targets(
        target, connect=connect, sandbox=sandbox, real_credentials=real_credentials,
        timeout=timeout, jobs=jobs, header=header, oauth=oauth, allow_network=allow_network,
        allow_install_scripts=allow_install_scripts,
    )  # fmt: skip
    for snapshot in targets.snapshots:
        out.rule(Text(reveal(f"{snapshot.name}  ({snapshot.origin.kind}: {snapshot.origin.ref})")))
        if not snapshot.tools_listed:
            out.print(Text("  tools not listed (add --connect)", style="dim"))
        for tf in iter_text_fields(snapshot):
            shown = reveal(tf.text)
            out.print(Text(tf.location.json_pointer or "", style="dim"))
            out.print(Text(f"  {shown}", style="bold yellow" if shown != tf.text else ""))


@app.command("flows")
def flows_cmd(
    target: TargetArg = None,
    connect: ConnectOpt = False,
    sandbox: SandboxOpt = SandboxMode.DOCKER,
    real_credentials: RealCredentialsOpt = False,
    timeout: TimeoutOpt = 60.0,
    jobs: JobsOpt = 4,
) -> None:
    """Show each client's tool capabilities and the toxic flows between them."""
    targets, _ = _targets(
        target, connect=connect, sandbox=sandbox, real_credentials=real_credentials,
        timeout=timeout, jobs=jobs,
    )  # fmt: skip
    flow_rules = [r for r in load_rules(plugins=False) if r.category is Category.TOXIC_FLOW]
    short = {
        CapabilityLabel.INGESTS_UNTRUSTED_CONTENT: "untrusted-in",
        CapabilityLabel.READS_PRIVATE_DATA: "private-data",
        CapabilityLabel.EXTERNAL_COMMUNICATION: "sends-out",
        CapabilityLabel.EXECUTES_CODE: "runs-code",
        CapabilityLabel.WRITES_FILES: "writes-files",
        CapabilityLabel.DESTRUCTIVE: "destructive",
    }
    for client, inventory in inventories(targets.snapshots).items():
        caps = inventory_capabilities(inventory)
        out.rule(Text(f"{client or 'snapshots'}: {len(inventory)} server(s)"))
        if not caps:
            out.print(Text("  no labelled tools (add --connect to list tools)", style="dim"))
            continue
        table = Table("Tool", "Capabilities", "Source")
        for cap in caps:
            labels = ", ".join(short.get(label, label.value) for label in cap.labels)
            source = "known server" if cap.known else "listed"
            table.add_row(Text(reveal(cap.qualified)), labels,
                          source + (", auto-approved" if cap.auto_approved else ""))  # fmt: skip
        out.print(table)
        result = run_scan(inventory, flow_rules)
        for f in result.findings:
            badge = Text(f" {f.severity.value.upper()} ", style=terminal.SEVERITY_STYLE[f.severity])
            out.print(badge + Text(f" {f.rule_id} {reveal(f.rationale)}"), soft_wrap=True)
        if not result.findings:
            out.print(Text("  no toxic flows", style="green"))


@app.command("rules")
def list_rules(plugins: PluginsOpt = True) -> None:
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
    _fail(f"`mcpiranha {command}` is planned for {phase} (see docs/ARCHITECTURE.md §10).")


@app.command()
def bench() -> None:
    """Score a classifier or LLM against the fixture corpus."""
    _planned("bench", "Phase 2")


@app.command()
def serve() -> None:
    """Run mcpiranha itself as an MCP server."""
    _planned("serve", "Phase 5")


@app.command()
def proxy() -> None:
    """Run as a runtime guard between an MCP client and server."""
    _planned("proxy", "Phase 5")
