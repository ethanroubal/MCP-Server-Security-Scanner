"""Cross-server toxic flows on real servers: realistic setups, and the base rate on random ones.

Usage: uv run python calibration/flows_review.py --run 2026-10-22-v2 [--random 1000]

Calibration scans each server alone, so it can't show cross-server flows. This combines the run's
saved snapshots into one client, as if a user had installed them together, and reports what
MCP-TF-001 / MCP-TF-002 find. The random part measures how often a flow fires on arbitrary
three-server setups: if nearly every setup is flagged, the finding carries no information.
"""

from __future__ import annotations

import argparse
import random
from collections import Counter
from pathlib import Path

from mcpiranha.core.io import load_snapshots
from mcpiranha.core.models import Origin, ServerSnapshot, Severity
from mcpiranha.core.pipeline import scan
from mcpiranha.rules import load_rules

HERE = Path(__file__).parent

# Setups people plausibly run, by server-name substring.
SETUPS: dict[str, list[str]] = {
    "dev: gitlab + desktop-commander + chrome-devtools + context7":
        ["zereight_mcp-gitlab", "desktop-commander", "chrome-devtools", "context7"],
    "office: ms-365 + google workspace + toggl":
        ["ms-365", "workspace-mcp", "togglhq"],
    "data: mongodb + clickhouse + airtable + tavily":
        ["npm_mongodb", "clickhouse", "airtable", "tavily"],
    "research: brave search + firecrawl + excel":
        ["brave-search", "firecrawl", "excel"],
    "QA: browserstack + mobile + sentry":
        ["browserstack", "mobile-mcp", "sentry"],
    "read-only dev tooling: context7 + repomix + nx + figma":
        ["context7", "repomix", "nx-mcp", "figma"],
    "ops: terraform + sentry + railway + homelab monitor":
        ["terraform", "sentry", "railway", "homelab"],
    "search + files: searxng + desktop-commander":
        ["searxng", "desktop-commander"],
}  # fmt: skip


def as_client(snapshots: list[ServerSnapshot]) -> list[ServerSnapshot]:
    """Put the servers in one (made-up) client, as if installed together."""
    return [s.model_copy(update={"origin": Origin(kind="config", client="review", ref=s.name),
                                 "id": f"review:{s.name}"}) for s in snapshots]  # fmt: skip


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run", required=True)
    parser.add_argument("--random", type=int, default=1000)
    options = parser.parse_args()

    listed = [s for p in sorted((HERE / "results" / options.run / "snapshots").glob("*.json"))
              for s in load_snapshots(p) if s.tools_listed]  # fmt: skip
    rules = [r for r in load_rules(plugins=False) if r.id.startswith("MCP-TF")]

    for title, wanted in SETUPS.items():
        chosen = [s for w in wanted for s in listed if w in s.name][: len(wanted)]
        names = [s.name for s in chosen]
        print(f"\n== {title}  ({len(chosen)}/{len(wanted)} found)")
        findings = scan(as_client(chosen), rules).findings
        for f in findings:
            print(f"  {f.severity.value.upper():8} {f.rule_id}: {f.rationale[:300]}")
        if not findings:
            print("  no toxic flows", names)

    rng = random.Random(0)
    counts: Counter[str] = Counter()
    for _ in range(options.random):
        sample = as_client(rng.sample(listed, 3))
        for f in scan(sample, rules).findings:
            if f.severity.rank >= Severity.HIGH.rank:
                counts[f.rule_id] += 1
    print(f"\nrandom 3-server setups ({options.random}): share with a high/critical flow finding")
    for rule_id in ("MCP-TF-001", "MCP-TF-002"):
        print(f"  {rule_id}: {counts[rule_id] / options.random:.0%}")


if __name__ == "__main__":
    main()
