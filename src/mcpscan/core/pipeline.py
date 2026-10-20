"""Run analyzers over snapshots and collect a `ScanResult`."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

from mcpscan import __version__
from mcpscan.core.models import Finding, ScannedServer, ScanResult, ServerSnapshot
from mcpscan.rules.base import Rule, RuleContext


def scan(snapshots: Sequence[ServerSnapshot], rules: Sequence[Rule]) -> ScanResult:
    started_at = datetime.now(UTC)
    findings: list[Finding] = []
    errors: list[str] = []
    for snapshot in snapshots:
        ctx = RuleContext(snapshot=snapshot, inventory=snapshots)
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
            ScannedServer(id=s.id, name=s.name, origin=s.origin, hashes=s.hashes())
            for s in snapshots
        ],
        findings=sorted(unique, key=lambda f: (-f.severity.rank, f.rule_id, f.location.server_id)),
        errors=errors,
    )
