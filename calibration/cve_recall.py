"""Recall of the taint rules (MCP-SRC-1xx) on real MCP servers with published injection CVEs.

Usage: uv run python calibration/cve_recall.py

Each case is a vulnerable release and the release that fixed it, downloaded from the registry
(hash-checked, read in memory, never installed or run). A correct analysis flags the vulnerable
release with the expected rule and stays quiet on the fix. Add cases as advisories are published.
"""

from __future__ import annotations

import anyio

from mcpiranha.core.models import Launch, Origin, ServerSnapshot
from mcpiranha.core.pipeline import scan
from mcpiranha.rules import load_rules
from mcpiranha.source import collect
from mcpiranha.supply import enrich

# (advisory, rule, vulnerable npm spec, fixed npm spec)
CASES = [
    ("CVE-2025-53355", "MCP-SRC-101", "mcp-server-kubernetes@2.4.9", "mcp-server-kubernetes@2.5.0"),
    ("CVE-2025-52573", "MCP-SRC-101", "ios-simulator-mcp@1.3.2", "ios-simulator-mcp@1.3.3"),
]


def _snapshot(spec: str) -> ServerSnapshot:
    return ServerSnapshot(id=f"cve:{spec}", name=spec,
                          origin=Origin(kind="config", client="cve", ref=spec),
                          launch=Launch(transport="stdio", command="npx", args=["-y", spec]),
                          tools_listed=False)  # fmt: skip


def main() -> None:
    specs = [s for _, _, vulnerable, fixed in CASES for s in (vulnerable, fixed)]

    async def fetch() -> list[ServerSnapshot]:
        snapshots, warnings = await enrich([_snapshot(s) for s in specs])
        snapshots, more = await collect(snapshots)
        for warning in [*warnings, *more]:
            print("warning:", warning)
        return snapshots

    by_spec = {s.name: s for s in anyio.run(fetch)}
    rules = [r for r in load_rules(plugins=False) if r.id.startswith("MCP-SRC-1")]
    caught = clean = 0
    for advisory, rule, vulnerable, fixed in CASES:
        found = {f.rule_id for f in scan([by_spec[vulnerable]], rules).findings}
        after = {f.rule_id for f in scan([by_spec[fixed]], rules).findings}
        caught += rule in found
        clean += not after
        before = "flagged" if rule in found else "MISSED"
        fix = "clean" if not after else "flagged: " + ", ".join(sorted(after))
        print(f"{advisory}: {vulnerable} {before} ({rule}); {fixed} {fix}")
    print(f"\n{caught}/{len(CASES)} vulnerable releases flagged, {clean}/{len(CASES)} fixes clean")


if __name__ == "__main__":
    main()
