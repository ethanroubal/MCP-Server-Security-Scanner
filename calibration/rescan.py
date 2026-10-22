"""Rescan a calibration run's saved snapshots with the current rules, without launching anything.

Usage: uv run python calibration/rescan.py --from 2026-10-22 --to 2026-10-22-tuned

Writes reports to calibration/results/<to>/reports/ in the same shape as run.py (connection
warnings are carried over from the original reports), so report.py can summarize the result and
the two runs can be compared directly.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from mcpscan.core.io import load_snapshots
from mcpscan.core.pipeline import scan
from mcpscan.report import json_report
from mcpscan.rules import load_rules

HERE = Path(__file__).parent


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--from", dest="source", required=True)
    parser.add_argument("--to", dest="target", required=True)
    options = parser.parse_args()

    source, target = HERE / "results" / options.source, HERE / "results" / options.target
    (target / "reports").mkdir(parents=True, exist_ok=True)
    rules = load_rules(plugins=False)
    count = 0
    for path in sorted((source / "snapshots").glob("*.json")):
        snapshots = load_snapshots(path)
        name = snapshots[0].id.rsplit(":", 1)[-1]  # run.py names each server after its target
        original = source / "reports" / f"{name}.json"
        warnings = json.loads(original.read_text(encoding="utf-8"))["warnings"] if (
            original.is_file()
        ) else []  # fmt: skip
        result = scan(snapshots, rules).model_copy(update={"warnings": warnings})
        (target / "reports" / f"{name}.json").write_text(json_report.render(result), "utf-8")
        count += 1
    print(f"rescanned {count} snapshots -> {target / 'reports'}")


if __name__ == "__main__":
    main()
