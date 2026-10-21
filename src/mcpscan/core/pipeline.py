"""Run analyzers over snapshots and collect a `ScanResult`."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from datetime import UTC, datetime

from mcpscan import __version__
from mcpscan.core.lockfile import Lockfile
from mcpscan.core.models import Finding, ScannedServer, ScanResult, ServerSnapshot
from mcpscan.rules.base import Rule, RuleContext


def inventories(snapshots: Sequence[ServerSnapshot]) -> dict[str, list[ServerSnapshot]]:
    """Group servers by the client that loads them: those are the tools one agent sees together.
    The same server configured in two clients must not be reported as colliding with itself."""
    groups: dict[str, list[ServerSnapshot]] = defaultdict(list)
    for snapshot in snapshots:
        groups[snapshot.origin.client or ""].append(snapshot)
    return groups


def scan(
    snapshots: Sequence[ServerSnapshot], rules: Sequence[Rule], *, lock: Lockfile | None = None
) -> ScanResult:
    started_at = datetime.now(UTC)
    findings: list[Finding] = []
    errors: list[str] = []
    groups = inventories(snapshots)
    for snapshot in snapshots:
        ctx = RuleContext(snapshot=snapshot, inventory=groups[snapshot.origin.client or ""],
                          lock=lock)  # fmt: skip
        for rule in rules:
            try:
                findings.extend(rule.run(ctx))
            except Exception as exc:  # one broken rule must not hide the others' results
                errors.append(f"{rule.id} failed on server {snapshot.name!r}: {exc!r}")

    unique = {f.id: f for f in findings}.values()
    return ScanResult(
        scanner_version=__version__,
        started_at=started_at,
        servers=[
            ScannedServer(
                id=s.id, name=s.name, origin=s.origin, hashes=s.hashes(), package=s.package
            )
            for s in snapshots
        ],
        findings=sorted(unique, key=lambda f: (-f.severity.rank, f.rule_id, f.location.server_id)),
        errors=errors,
    )
