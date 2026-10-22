"""Summarize a calibration run for review: calibration/results/<run>/REPORT.md and labels.yaml.

Usage: uv run python calibration/report.py [--run NAME]

REPORT.md: coverage (which servers could be listed and why not), then every finding grouped by
rule, with the evidence revealed. labels.yaml: one entry per finding with an empty `verdict` to
fill in (tp / fp / unsure); re-running keeps verdicts already filled in.
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml

from mcpscan.core.text import reveal

HERE = Path(__file__).parent
SEVERITIES = ("critical", "high", "medium", "low", "info")


def short(text: str, limit: int = 220) -> str:
    text = " ".join(reveal(text).split())
    return text if len(text) <= limit else text[:limit] + "…"


def failure_reason(warning: str) -> str:
    for pattern, label in (
        (r"requires authentication", "needs credentials"),
        (r"Docker daemon", "docker not running"),
        (r"docker pull failed|manifest unknown|not found", "image/package not found"),
        (
            r"docker run failed|npm ERR|No solution found|only-binary|couldn't find its executable",
            "install failed",
        ),
        (r"within \d+s", "timed out"),
        (r"Connection closed", "server exited"),
    ):
        if re.search(pattern, warning, re.IGNORECASE):
            return label
    return "other"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run", default=datetime.date.today().isoformat())
    run_dir = HERE / "results" / parser.parse_args().run

    targets = {
        re.sub(r"[^A-Za-z0-9._-]+", "_", f"{t['registry']}_{t['package']}").strip("_"): t
        for t in json.loads((HERE / "targets.json").read_text(encoding="utf-8"))
    }
    reports: dict[str, dict[str, Any]] = {
        p.stem: json.loads(p.read_text(encoding="utf-8"))
        for p in sorted((run_dir / "reports").glob("*.json"))
    }

    listed, failed = [], {}
    by_rule: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    for name, report in reports.items():
        servers = report.get("servers", [])
        if report.get("warnings"):
            failed[name] = report["warnings"][0]
        elif servers:
            listed.append(name)
        for finding in report.get("findings", []):
            by_rule[finding["rule_id"]].append((name, finding))
    missing = sorted(set(targets) - set(reports))

    lines = [f"# Calibration run {run_dir.name}", ""]
    lines += [
        f"- Targets: {len(targets)}; reports: {len(reports)}; tools listed: {len(listed)}; "
        f"could not list: {len(failed)}; no report (crashed/timed out): {len(missing)}",
        "",
        "## Could not list",
        "",
    ]
    for reason, count in Counter(failure_reason(w) for w in failed.values()).most_common():
        lines.append(f"- {reason}: {count}")
    for name, warning in sorted(failed.items()):
        lines.append(f"  - `{name}`: {short(warning, 300)}")
    for name in missing:
        lines.append(f"  - `{name}`: no report")

    lines += ["", "## Findings by rule", "", "| Rule | Servers flagged | " +
              " | ".join(SEVERITIES) + " |", "|---|---|" + "---|" * len(SEVERITIES)]  # fmt: skip
    for rule in sorted(by_rule):
        hits = by_rule[rule]
        sev = Counter(f["severity"] for _, f in hits)
        servers = len({n for n, _ in hits})
        lines.append(f"| {rule} | {servers} / {len(listed)} | "
                     + " | ".join(str(sev.get(s, "")) for s in SEVERITIES) + " |")  # fmt: skip

    labels_path = run_dir / "labels.yaml"
    old = yaml.safe_load(labels_path.read_text(encoding="utf-8")) if labels_path.is_file() else []
    verdicts = {e["finding_id"]: e for e in (old or [])}
    labels: list[dict[str, Any]] = []
    for rule in sorted(by_rule):
        lines += ["", f"### {rule}", ""]
        for name, f in sorted(by_rule[rule], key=lambda x: SEVERITIES.index(x[1]["severity"])):
            loc = f["location"]
            item = loc.get("tool") or loc.get("prompt") or loc.get("resource")
            where = "/".join(filter(None, [item, loc.get("json_pointer")]))
            downloads = targets.get(name, {}).get("monthly_downloads", "?")
            lines.append(f"- **{f['severity']}** `{name}` ({downloads}/mo) {where}  ")
            lines.append(f"  {short(f['rationale'])}  ")
            if f["evidence"]:
                lines.append(f"  evidence: `{short(f['evidence'][0]['text'], 160)}`  ")
            lines.append(f"  id `{f['id']}`")
            previous = verdicts.get(f["id"], {})
            labels.append({"finding_id": f["id"], "rule": rule, "server": name,
                           "severity": f["severity"], "verdict": previous.get("verdict", ""),
                           "note": previous.get("note", "")})  # fmt: skip

    (run_dir / "REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    labels_path.write_text(yaml.safe_dump(labels, sort_keys=False, allow_unicode=False),
                           encoding="utf-8")  # fmt: skip
    print(f"wrote {run_dir / 'REPORT.md'} and {labels_path} ({len(labels)} findings)")


if __name__ == "__main__":
    main()
