"""Supply-chain (MCP-SC) and source (MCP-SRC) rules on the calibration targets.

Usage: uv run python calibration/supply_review.py [--unpinned] [--source]

Looks every npm and PyPI target up on the public registries and osv.dev (responses are cached for
an hour) and runs only the MCP-SC rules, launching nothing. --source also downloads each
release's archive (checked against the registry's hash, read in memory) and runs the MCP-SRC
rules. Targets are pinned to their registry versions; --unpinned drops the versions, as most real
configs do (`npx -y pkg`), so the newest release is judged instead.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

import anyio

from mcpiranha.core.models import Launch, Origin, ServerSnapshot
from mcpiranha.core.pipeline import scan
from mcpiranha.rules import load_rules
from mcpiranha.source import collect
from mcpiranha.supply import enrich

HERE = Path(__file__).parent


def snapshot(target: dict[str, Any], unpinned: bool) -> ServerSnapshot:
    config = target["config"]
    args = [str(a) for a in config.get("args", [])]
    if unpinned and target["version"]:
        sep = "==" if target["registry"] == "pypi" else "@"
        args = [a.replace(f"{sep}{target['version']}", "") for a in args]
    name = target["package"]
    return ServerSnapshot(id=f"supply:{name}", name=name,
                          origin=Origin(kind="config", client="supply", ref=name),
                          launch=Launch(transport="stdio", command=config["command"], args=args),
                          tools_listed=False)  # fmt: skip


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--unpinned", action="store_true")
    parser.add_argument("--source", action="store_true")
    options = parser.parse_args()

    targets = [t for t in json.loads((HERE / "targets.json").read_text())
               if t["registry"] in ("npm", "pypi")]  # fmt: skip
    snapshots, warnings = anyio.run(
        lambda: enrich([snapshot(t, options.unpinned) for t in targets])
    )
    prefixes = ("MCP-SC", "MCP-SRC") if options.source else ("MCP-SC",)
    if options.source:
        snapshots, source_warnings = anyio.run(lambda: collect(snapshots))
        warnings += source_warnings
        trees = [s.source for s in snapshots if s.source]
        print(f"source: {len(trees)} archives, {sum(t.files for t in trees)} files analyzed")
        for tree in trees:
            for skipped in tree.skipped:
                print(f"  skipped in {tree.root}: {skipped}")
    for warning in warnings:
        print("warning:", warning)
    rules = [r for r in load_rules(plugins=False) if r.id.startswith(prefixes)]
    findings = scan(snapshots, rules).findings
    looked_up = sum(bool(s.package and s.package.checked_at) for s in snapshots)
    print(f"{looked_up}/{len(targets)} npm/PyPI targets looked up "
          f"({'newest releases' if options.unpinned else 'pinned versions'})\n")  # fmt: skip
    servers = Counter[str]()
    for f in sorted(findings, key=lambda f: (f.rule_id, f.severity.rank)):
        servers[f.rule_id] += 1
        print(f"{f.rule_id} {f.severity.value:8} {f.rationale[:400]}")
    print()
    for rule in rules:
        print(f"{rule.id}: {servers[rule.id]} target(s)")


if __name__ == "__main__":
    main()
