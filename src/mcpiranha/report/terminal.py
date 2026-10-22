"""Human-readable terminal report.

Everything that came from a scanned server (names, descriptions, evidence) is attacker-controlled.
It goes through `reveal()` and is printed as `rich.text.Text`, never as a markup string, so it can't
inject Rich markup or terminal escape sequences into our output.
"""

from __future__ import annotations

from collections import Counter

from rich.console import Console
from rich.text import Text

from mcpiranha.core.models import Finding, ScanResult, Severity
from mcpiranha.core.text import reveal

SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
_MAX_EVIDENCE_SHOWN = 5
_MAX_EVIDENCE_CHARS = 160  # of revealed text; the JSON report always has the full evidence


def _clip(text: str) -> str:
    if len(text) <= _MAX_EVIDENCE_CHARS:
        return text
    return f"{text[:_MAX_EVIDENCE_CHARS]}… (+{len(text) - _MAX_EVIDENCE_CHARS} chars)"


def _where(finding: Finding, server_names: dict[str, str]) -> str:
    loc = finding.location
    parts = [f"server {server_names.get(loc.server_id, loc.server_id)!r}"]
    for label, value in (("tool", loc.tool), ("prompt", loc.prompt), ("resource", loc.resource)):
        if value:
            parts.append(f"{label} {value!r}")
    if loc.file:
        parts.append(f"{loc.file}:{loc.line}" if loc.line else loc.file)
    if loc.json_pointer:
        parts.append(loc.json_pointer)
    return reveal(" · ".join(parts))


def _line(label: str, value: str, style: str = "") -> Text:
    return Text(f"  {label:<9}", style="dim") + Text(value, style=style)


def render(result: ScanResult, console: Console) -> None:
    names = {s.id: s.name for s in result.servers}

    for f in result.findings:
        header = Text()
        header.append(f" {f.severity.value.upper()} ", style=SEVERITY_STYLE[f.severity])
        header.append(f" {f.rule_id} ", style="bold")
        header.append(f.title)
        console.print(header)
        console.print(_line("where", _where(f, names)))
        console.print(_line("why", reveal(f.rationale)))
        for ev in f.evidence[:_MAX_EVIDENCE_SHOWN]:
            console.print(_line("evidence", _clip(reveal(ev.text)), style="magenta"))
        if len(f.evidence) > _MAX_EVIDENCE_SHOWN:
            console.print(_line("", f"… {len(f.evidence) - _MAX_EVIDENCE_SHOWN} more", "dim"))
        console.print(_line("fix", f.remediation))
        console.print()

    counts = Counter(f.severity for f in result.findings)
    summary = Text(f"Scanned {len(result.servers)} server(s): ")
    if not result.findings:
        summary.append("no findings", style="bold green")
    else:
        summary.append(f"{len(result.findings)} finding(s) ")
        summary.append_text(
            Text(", ").join(
                Text(f"{counts[s]} {s.value}", style=SEVERITY_STYLE[s])
                for s in sorted(counts, key=lambda s: -s.rank)
            )
        )
    if result.suppressed:
        summary.append(f" ({len(result.suppressed)} suppressed by policy)", style="dim")
    console.print(summary)

    for warning in result.warnings:
        console.print(Text(f"warning: {reveal(warning)}", style="yellow"))
    for error in result.errors:
        console.print(Text(f"error: {reveal(error)}", style="red"))
