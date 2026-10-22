"""MCP-CF-004: launch commands that run with excessive privilege or execute downloaded code.

`curl ... | sh` runs whatever the URL serves today. `sudo` gives the server root. A privileged
container or a mounted Docker socket is root on the host with extra steps.
"""

from __future__ import annotations

import re
from pathlib import PurePath

from mcpiranha.core.launch import command_line, docker_run
from mcpiranha.core.models import Category, Evidence, Finding, Location, Severity
from mcpiranha.rules.base import Rule, RuleContext
from mcpiranha.rules.builtin.broad_filesystem import is_home, is_root
from mcpiranha.rules.registry import register

_PIPE_TO_SHELL = re.compile(
    r"\b(curl|wget|fetch|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^|;&]*\|\s*"
    r"(sudo\s+)?(sh|bash|zsh|dash|ksh|python3?|node|perl|ruby|iex|Invoke-Expression)\b",
    re.IGNORECASE,
)
_DOWNLOAD_EXEC = re.compile(
    r"\b(iex|Invoke-Expression)\b.{0,40}\b(DownloadString|iwr|irm|Invoke-WebRequest|"
    r"Invoke-RestMethod)\b|\b(sh|bash)\s+<\(\s*(curl|wget)\b",
    re.IGNORECASE,
)
_PRIV_ESCALATION = frozenset({"sudo", "doas", "pkexec", "runas", "gsudo"})


def _volume_source(flag: str, value: str) -> str | None:
    if flag in ("-v", "--volume"):
        return value.split(":", 1)[0] if not re.match(r"^[A-Za-z]:\\", value) else value[:2]
    if flag == "--mount":
        for part in value.split(","):
            key, _, val = part.partition("=")
            if key in ("source", "src"):
                return val
    return None


@register
class DangerousLauncher(Rule):
    id = "MCP-CF-004"
    title = "Dangerous launch command"
    category = Category.CONFIG
    default_severity = Severity.HIGH
    applies_to = frozenset({"config"})
    remediation = (
        "Launch the server from a pinned package or image with no extra privileges. Don't pipe "
        "downloads into a shell, run servers as root, or give containers host-level access."
    )

    def run(self, ctx: RuleContext) -> list[Finding]:
        launch = ctx.snapshot.launch
        if launch is None or not launch.command:
            return []
        argv = command_line(launch)
        joined = " ".join(argv)
        issues: list[tuple[Severity, str, str]] = []  # (severity, why, evidence)

        if (m := _PIPE_TO_SHELL.search(joined)) or (m := _DOWNLOAD_EXEC.search(joined)):
            issues.append((Severity.HIGH, "pipes downloaded code into an interpreter", m.group()))
        if PurePath(argv[0]).name.lower() in _PRIV_ESCALATION:
            issues.append((Severity.HIGH, "runs the server with elevated privileges", argv[0]))

        if (run := docker_run(launch)) is not None:
            for flag, value in run.options:
                text = flag if value is None else f"{flag} {value}"
                lowered = (value or "").lower()
                if flag == "--privileged":
                    issues.append(
                        (Severity.HIGH, "runs a privileged container (root on the host)", text)
                    )
                elif flag == "--cap-add" and lowered in ("all", "sys_admin", "sys_ptrace"):
                    issues.append((Severity.HIGH, f"adds the {value} capability", text))
                elif flag == "--security-opt" and "unconfined" in lowered:
                    issues.append((Severity.HIGH, "disables container confinement", text))
                elif flag in ("--pid", "--ipc", "--uts", "--userns") and lowered == "host":
                    issues.append((Severity.MEDIUM, f"shares the host {flag[2:]} namespace", text))
                elif flag in ("--network", "--net") and lowered == "host":
                    issues.append((Severity.MEDIUM, "uses the host network", text))
                elif value and (source := _volume_source(flag, value)) is not None:
                    if source.endswith("docker.sock"):
                        issues.append((Severity.HIGH, "mounts the Docker socket (host root)", text))
                    elif is_root(source):
                        issues.append((Severity.HIGH, "mounts the host's root filesystem", text))
                    elif is_home(source):
                        issues.append((Severity.MEDIUM, "mounts your home directory", text))

        if not issues:
            return []
        return [
            self.finding(
                location=Location(
                    server_id=ctx.snapshot.id,
                    json_pointer="/launch",
                    file=ctx.snapshot.origin.config_path,
                ),
                evidence=[Evidence(text=text) for _, _, text in issues],
                rationale="The launch command " + "; ".join(why for _, why, _ in issues) + ".",
                severity=max((s for s, _, _ in issues), key=lambda s: s.rank),
            )
        ]
