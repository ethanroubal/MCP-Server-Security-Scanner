"""MCP-SC: what the registries and OSV say about the package a server runs.

These rules judge facts gathered by `mcpiranha.supply` before the scan (they don't touch the
network themselves), so they only fire when that lookup ran (not with `--offline`):

- SC-001: the resolved version has a known vulnerability, or is a known malicious package.
- SC-002: the package runs code when installed (npm lifecycle scripts, a PyPI sdist's setup.py);
  worst when the release just added it, the usual shape of a hijacked package.
- SC-003: the release lost the provenance earlier releases had, or comes from another repository:
  published from somewhere other than the project's CI, e.g. with a stolen token.
- SC-004: the package is only days old. (Not new releases: popular MCP servers release almost
  daily, so calibration found a fresh release on 31 of 84 unpinned servers.)
- SC-005: the release was published by an npm account that never published it before.
- SC-006: the package is deprecated, the release was yanked, or the name isn't on the registry.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from mcpiranha.core.launch import argv_pointer, command_line, package_ref
from mcpiranha.core.models import (
    Category,
    Confidence,
    Evidence,
    Finding,
    Location,
    PackageMeta,
    Severity,
)
from mcpiranha.rules.base import Rule, RuleContext
from mcpiranha.rules.registry import register

NEW_PACKAGE_DAYS = 30


class _PackageRule(Rule):
    category = Category.SUPPLY_CHAIN
    applies_to = frozenset({"package"})

    def _package(self, ctx: RuleContext) -> PackageMeta | None:
        p = ctx.snapshot.package
        return p if p is not None and (p.version or p.removed) and p.checked_at else None

    def _report(self, ctx: RuleContext, package: PackageMeta, rationale: str, severity: Severity,
                confidence: Confidence = Confidence.HIGH) -> Finding:  # fmt: skip
        launch, ref = ctx.snapshot.launch, package_ref(ctx.snapshot.launch)
        pointer = argv_pointer(launch, ref.argv_index) if launch and ref else "/launch"
        evidence = command_line(launch)[ref.argv_index] if launch and ref else package.name
        return self.finding(
            location=Location(
                server_id=ctx.snapshot.id,
                json_pointer=pointer,
                file=ctx.snapshot.origin.config_path,
            ),
            evidence=[Evidence(text=evidence)],
            rationale=rationale,
            severity=severity,
            confidence=confidence,
        )


def _label(p: PackageMeta) -> str:
    how = {
        "latest": " (the newest release, which runs with no version pinned)",
        "range": " (what the version range resolves to now)",
    }.get(p.resolution or "", "")
    return f"{p.registry} {p.name} {p.version}{how}" if p.version else f"{p.registry} {p.name}"


def _owner(source: str) -> str:
    """ "GitHub:owner/repo" -> "github:owner"."""
    return source.rsplit("/", 1)[0].lower()


def _days(later: datetime, earlier: datetime) -> float:
    return (later - earlier) / timedelta(days=1)


@register
class KnownVulnerability(_PackageRule):
    id = "MCP-SC-001"
    title = "Known vulnerability or malicious package"
    default_severity = Severity.HIGH
    remediation = (
        "Upgrade to a fixed version and pin it. For a malicious package, remove it, then treat "
        "every secret the server could read (its env, your files) as stolen and rotate them."
    )
    references = ("https://osv.dev",)

    def run(self, ctx: RuleContext) -> list[Finding]:
        p = self._package(ctx)
        if p is None or not p.vulnerabilities:
            return []
        findings: list[Finding] = []
        malicious = [v for v in p.vulnerabilities if v.id.startswith("MAL-")]
        if malicious:
            ids = ", ".join(v.id for v in malicious)
            findings.append(self._report(ctx, p, f"{_label(p)} is a known malicious package "
                                         f"({ids}).", Severity.CRITICAL))  # fmt: skip
        others = [v for v in p.vulnerabilities if not v.id.startswith("MAL-")]
        if others:
            worst = max((v.severity or Severity.MEDIUM for v in others), key=lambda s: s.rank)
            parts: list[str] = []
            ranked = sorted(others, key=lambda v: -(v.severity or Severity.MEDIUM).rank)
            for v in ranked[:5]:
                name = next((a for a in v.aliases if a.startswith("CVE-")), v.id)
                fixed = f", fixed in {', '.join(v.fixed)}" if v.fixed else ""
                parts.append(f"{name} ({(v.severity or Severity.MEDIUM).value}{fixed})"
                             + (f": {v.summary}" if v.summary else ""))  # fmt: skip
            if len(others) > 5:
                parts.append(f"and {len(others) - 5} more")
            findings.append(self._report(
                ctx, p, f"{_label(p)} has {len(others)} known vulnerabilit"
                f"{'y' if len(others) == 1 else 'ies'}: " + "; ".join(parts), worst))  # fmt: skip
        return findings


@register
class InstallScripts(_PackageRule):
    id = "MCP-SC-002"
    title = "Package runs code at install time"
    default_severity = Severity.LOW
    remediation = (
        "Install scripts run with your user's access as soon as npx/uvx fetches the package, "
        "before any MCP client sees a tool. Read what the script does; if the server works "
        "without it, run it with `--ignore-scripts` (npm) or `--only-binary :all:` (pip/uv)."
    )

    def run(self, ctx: RuleContext) -> list[Finding]:
        p = self._package(ctx)
        if p is None or not p.install_scripts:
            return []
        scripts = "; ".join(p.install_scripts)
        if p.previous is not None and not p.previous.install_scripts:
            return [self._report(ctx, p, f"{_label(p)} runs code when installed ({scripts}), and "
                                 f"the release before it ({p.previous.version}) didn't. Hijacked "
                                 "packages usually look like this.", Severity.HIGH)]  # fmt: skip
        return [self._report(ctx, p, f"{_label(p)} runs code when installed: {scripts}.",
                             Severity.LOW)]  # fmt: skip


@register
class ProvenanceChange(_PackageRule):
    id = "MCP-SC-003"
    title = "Release lost its build provenance or changed source repository"
    default_severity = Severity.HIGH
    remediation = (
        "Releases built by the project's CI carry provenance; one without it was published "
        "some other way, e.g. by hand or with a stolen token. Pin the previous release until "
        "the maintainers confirm this one."
    )

    def run(self, ctx: RuleContext) -> list[Finding]:
        p = self._package(ctx)
        prev = p.previous if p else None
        if p is None or prev is None:
            return []
        if prev.provenance and p.provenance is False:
            return [self._report(ctx, p, f"{_label(p)} has no provenance attestation, but the "
                                 f"release before it ({prev.version}) had one.",
                                 Severity.HIGH)]  # fmt: skip
        # A different owner, not a renamed repo (sirkirby/unifi-network-mcp -> sirkirby/unifi-mcp)
        if (p.provenance_source and prev.provenance_source
                and _owner(p.provenance_source) != _owner(prev.provenance_source)):  # fmt: skip
            return [self._report(ctx, p, f"{_label(p)} was built from {p.provenance_source}; "
                                 f"{prev.version} was built from {prev.provenance_source}.",
                                 Severity.HIGH)]  # fmt: skip
        return []


@register
class NewPackage(_PackageRule):
    id = "MCP-SC-004"
    title = "Very new package"
    default_severity = Severity.MEDIUM
    remediation = (
        "Malicious packages are usually found and removed within days of being published. "
        "Prefer packages with some history, and pin the version you reviewed."
    )

    def run(self, ctx: RuleContext) -> list[Finding]:
        p = self._package(ctx)
        if p is None or p.checked_at is None:
            return []
        if p.created_at and _days(p.checked_at, p.created_at) < NEW_PACKAGE_DAYS:
            age = _days(p.checked_at, p.created_at)
            return [self._report(ctx, p, f"{p.registry} package {p.name} was first published "
                                 f"{age:.0f} day(s) ago.", Severity.MEDIUM,
                                 Confidence.MEDIUM)]  # fmt: skip
        return []


@register
class NewPublisher(_PackageRule):
    id = "MCP-SC-005"
    title = "Release published by a new account"
    default_severity = Severity.MEDIUM
    remediation = (
        "Check the project's announcements or repository for the new maintainer. Until then, "
        "pin the last release published by a known account."
    )

    def run(self, ctx: RuleContext) -> list[Finding]:
        p = self._package(ctx)
        if p is None or not p.publisher or not p.earlier_publishers:
            return []
        if p.publisher in p.earlier_publishers or p.publisher.startswith("trusted publishing"):
            return []  # moving to CI trusted publishing is the good direction
        known = ", ".join(p.earlier_publishers)
        return [self._report(ctx, p, f"{_label(p)} was published by npm account "
                             f"{p.publisher!r}, which published none of the releases before it "
                             f"(those were published by: {known}).", Severity.MEDIUM,
                             Confidence.MEDIUM)]  # fmt: skip


@register
class Deprecated(_PackageRule):
    id = "MCP-SC-006"
    title = "Deprecated, yanked or missing package"
    default_severity = Severity.LOW
    remediation = (
        "Move to the replacement the deprecation notice names; deprecated packages stop getting "
        "security fixes. A removed package was taken down (often for malware) or never existed "
        "(a typo): find out which before anything runs it from a cache."
    )

    def run(self, ctx: RuleContext) -> list[Finding]:
        p = self._package(ctx)
        if p is not None and p.removed:
            return [self._report(ctx, p, f"{_label(p)} is not on {p.registry}: it was taken down, "
                                 "or never existed, in which case anyone can register the name "
                                 "and this config would run their code.",
                                 Severity.HIGH)]  # fmt: skip
        if p is not None and p.yanked:
            return [self._report(ctx, p, f"{_label(p)} was yanked by its maintainers: "
                                 f"{p.yanked}", Severity.MEDIUM)]  # fmt: skip
        if p is None or not p.deprecated:
            return []
        return [self._report(ctx, p, f"{_label(p)} is deprecated: {p.deprecated}", Severity.LOW)]
