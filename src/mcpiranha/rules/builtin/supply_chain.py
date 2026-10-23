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
                confidence: Confidence = Confidence.HIGH,
                about: str | None = None) -> Finding:  # fmt: skip
        """`about`: what this finding is about (an advisory, a dependency), so two findings of
        one rule on one package stay apart (finding ids hash rule, location and evidence)."""
        launch, ref = ctx.snapshot.launch, package_ref(ctx.snapshot.launch)
        pointer = argv_pointer(launch, ref.argv_index) if launch and ref else "/launch"
        evidence = command_line(launch)[ref.argv_index] if launch and ref else package.name
        return self.finding(
            location=Location(
                server_id=ctx.snapshot.id,
                json_pointer=pointer,
                file=ctx.snapshot.origin.config_path,
            ),
            evidence=[Evidence(text=evidence), *([Evidence(text=about)] if about else [])],
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
                                         f"({ids}).", Severity.CRITICAL, about=ids))  # fmt: skip
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
                f"{'y' if len(others) == 1 else 'ies'}: " + "; ".join(parts), worst,
                about=ranked[0].id))  # fmt: skip
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


# --- Dependencies (supply/deps.py): the same questions for everything the server installs ----


def _dependencies(p: PackageMeta) -> list[PackageMeta]:
    return p.dependencies or []


def _dep(d: PackageMeta) -> str:
    name = f"{d.name}@{d.version}" if d.version else d.name
    return f"{name} (via {' > '.join(d.via)})" if d.via else name


def _recent(d: PackageMeta, now: datetime | None) -> bool:
    """Published in the last NEW_PACKAGE_DAYS: hijacked releases are found and pulled within
    days, while maintainer changes and the odd manual publish happen all the time in old ones
    (calibration: 96 new publishers across the top servers' dependencies, none suspicious)."""
    return bool(now and d.published_at and _days(now, d.published_at) < NEW_PACKAGE_DAYS)


def _listed(items: list[str], limit: int = 5) -> str:
    more = f"; and {len(items) - limit} more" if len(items) > limit else ""
    return "; ".join(items[:limit]) + more


@register
class DependencyVulnerability(_PackageRule):
    id = "MCP-SC-007"
    title = "Known malicious or vulnerable dependency"
    default_severity = Severity.HIGH
    remediation = (
        "A malicious dependency runs with the server's access: remove the server (or pin a "
        "release without it) and rotate what it could read. For vulnerabilities, upgrade the "
        "server to a release that depends on fixed versions."
    )
    references = ("https://osv.dev",)

    def run(self, ctx: RuleContext) -> list[Finding]:
        p = self._package(ctx)
        if p is None:
            return []
        findings: list[Finding] = []
        malicious = [d for d in _dependencies(p)
                     if any(v.id.startswith("MAL-") for v in d.vulnerabilities or [])]  # fmt: skip
        if malicious:
            findings.append(self._report(ctx, p, f"{_label(p)} installs a known malicious "
                                         f"package: {_listed([_dep(d) for d in malicious])}.",
                                         Severity.CRITICAL, about=_dep(malicious[0])))  # fmt: skip
        vulnerable = [(d, [v for v in d.vulnerabilities or [] if not v.id.startswith("MAL-")])
                      for d in _dependencies(p)]  # fmt: skip
        vulnerable = [(d, vs) for d, vs in vulnerable if vs]
        if vulnerable:
            worst = max((v.severity or Severity.MEDIUM for _, vs in vulnerable for v in vs),
                        key=lambda s: s.rank)  # fmt: skip
            items = [f"{_dep(d)}: " + ", ".join(list(dict.fromkeys(
                next((a for a in v.aliases if a.startswith("CVE-")), v.id) for v in vs))[:3])
                for d, vs in sorted(vulnerable, key=lambda dv: -max(
                    (v.severity or Severity.MEDIUM).rank for v in dv[1]))]  # fmt: skip
            findings.append(self._report(ctx, p, f"{_label(p)} installs {len(vulnerable)} "
                                         f"dependenc{'y' if len(vulnerable) == 1 else 'ies'} with "
                                         f"known vulnerabilities: {_listed(items)}.",
                                         worst, Confidence.MEDIUM,
                                         about=f"{len(vulnerable)} vulnerable"))  # fmt: skip
        return findings


@register
class DependencyInstallScripts(_PackageRule):
    id = "MCP-SC-008"
    title = "Dependency runs code at install time"
    default_severity = Severity.LOW
    remediation = (
        "npx and uvx run these scripts as soon as they install the server. Many are builds of "
        "native code; one that a release just added is how hijacked packages spread. Check the "
        "script, or install with --ignore-scripts if the server works without it."
    )

    def run(self, ctx: RuleContext) -> list[Finding]:
        p = self._package(ctx)
        if p is None:
            return []
        scripted = [d for d in _dependencies(p) if d.install_scripts]
        if not scripted:
            return []
        added = [d for d in scripted if d.previous is not None and not d.previous.install_scripts
                 and _recent(d, p.checked_at)]  # fmt: skip
        if added:
            items = [f"{_dep(d)}: {d.install_scripts[0]} (not in {d.previous.version})"
                     for d in added if d.previous]  # fmt: skip
            return [self._report(ctx, p, f"{_label(p)} installs dependencies whose current "
                                 f"release added install scripts: {_listed(items)}.",
                                 Severity.HIGH)]  # fmt: skip
        items = [f"{_dep(d)}: {d.install_scripts[0]}" for d in scripted]
        return [self._report(ctx, p, f"{_label(p)} installs {len(scripted)} dependenc"
                             f"{'y' if len(scripted) == 1 else 'ies'} that run code when "
                             f"installed: {_listed(items)}.", Severity.LOW)]  # fmt: skip


@register
class SuspiciousDependency(_PackageRule):
    id = "MCP-SC-009"
    title = "Suspicious dependency"
    default_severity = Severity.MEDIUM
    remediation = (
        "Find out why the dependency looks like this before running the server: a name the "
        "registry doesn't have can be registered by anyone, git/URL dependencies skip the "
        "registry's checks, and a new publisher or missing provenance is how hijacked "
        "releases look."
    )

    def run(self, ctx: RuleContext) -> list[Finding]:
        p = self._package(ctx)
        if p is None or p.checked_at is None:
            return []
        reasons: list[tuple[Severity, str]] = []
        for d in _dependencies(p):
            if d.removed:
                reasons.append((Severity.HIGH, f"{_dep(d)} is not on {d.registry} (anyone can "
                                "publish that name)"))  # fmt: skip
            elif d.external:
                reasons.append((Severity.MEDIUM, f"{_dep(d)} comes from {d.external}, not the "
                                "registry"))  # fmt: skip
            prev = d.previous
            recent = _recent(d, p.checked_at)
            if recent and prev is not None and prev.provenance and d.provenance is False:
                reasons.append((Severity.HIGH, f"{_dep(d)} lost the provenance {prev.version} "
                                "had"))  # fmt: skip
            if (recent and d.publisher and d.earlier_publishers
                    and d.publisher not in d.earlier_publishers
                    and not d.publisher.startswith("trusted publishing")):  # fmt: skip
                reasons.append((Severity.MEDIUM, f"{_dep(d)} was published by {d.publisher!r}, "
                                "new to that package"))  # fmt: skip
            if d.created_at and _days(p.checked_at, d.created_at) < NEW_PACKAGE_DAYS:
                age = _days(p.checked_at, d.created_at)
                reasons.append((Severity.MEDIUM, f"{_dep(d)} is {age:.0f} day(s) old"))
        if not reasons:
            return []
        worst = max((s for s, _ in reasons), key=lambda s: s.rank)
        ordered = [r for _, r in sorted(reasons, key=lambda sr: -sr[0].rank)]
        return [self._report(ctx, p, f"{_label(p)} has suspicious dependencies: "
                             f"{_listed(ordered)}.", worst, Confidence.MEDIUM)]  # fmt: skip
