"""Scan every server in calibration/targets.json with `mcpiranha scan --connect` (Docker sandbox).

Usage: uv run python calibration/run.py [--run NAME] [--jobs 4] [--timeout 120] [--only SUBSTRING]

Each target is scanned on its own, from its own directory, as a project `.mcp.json`. That keeps
cross-server rules from pairing up unrelated servers and keeps any local .mcpiranha.yaml out of
it. Re-running the same --run skips targets that already have a report, so it can be resumed.

Output in calibration/results/<run>/: reports/*.json (mcpiranha JSON reports), snapshots/*.json
(what each server served, for offline rescans), logs/*.log (mcpiranha's stderr).
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

HERE = Path(__file__).parent


def slug(target: dict[str, Any]) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", f"{target['registry']}_{target['package']}").strip("_")


def scan(target: dict[str, Any], run_dir: Path, timeout: float, extra: list[str]) -> str:
    name = slug(target)
    report = run_dir / "reports" / f"{name}.json"
    if report.is_file():
        return f"skip   {name}"
    project = run_dir / "projects" / name
    project.mkdir(parents=True, exist_ok=True)
    (project / ".mcp.json").write_text(
        json.dumps({"mcpServers": {name: target["config"]}}, indent=2), encoding="utf-8"
    )
    command = [
        str(Path(sys.executable).with_name("mcpiranha")), "scan", ".", "--connect", "--no-lock",
        "--timeout", str(timeout), "--jobs", "1", "-f", "json", "-o", str(report.resolve()),
        "--save-snapshots", str((run_dir / "snapshots").resolve()), *extra,
    ]  # fmt: skip
    log = run_dir / "logs" / f"{name}.log"
    try:
        done = subprocess.run(command, cwd=project, capture_output=True, text=True,
                              timeout=timeout * 3 + 600)  # fmt: skip
        log.write_text(done.stdout + done.stderr, encoding="utf-8")
        status = {0: "ok", 1: "ok*", 2: "error"}.get(done.returncode, f"exit {done.returncode}")
    except subprocess.TimeoutExpired:
        log.write_text("calibration runner: timed out\n", encoding="utf-8")
        status = "timeout"
    return f"{status:<6} {name}"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run", default=datetime.date.today().isoformat())
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--only", help="only targets whose package contains this text")
    parser.add_argument("--targets", type=Path, default=HERE / "targets.json")
    parser.add_argument("--allow-network", action="store_true")
    parser.add_argument("--allow-install-scripts", action="store_true")
    options = parser.parse_args()

    targets = json.loads(options.targets.read_text(encoding="utf-8"))
    extra = [
        flag
        for flag, on in (
            ("--allow-network", options.allow_network),
            ("--allow-install-scripts", options.allow_install_scripts),
        )
        if on
    ]
    if options.only:
        targets = [t for t in targets if options.only in t["package"]]
    run_dir = HERE / "results" / options.run
    for sub in ("reports", "snapshots", "logs", "projects"):
        (run_dir / sub).mkdir(parents=True, exist_ok=True)
    print(f"{len(targets)} targets -> {run_dir}", flush=True)
    with ThreadPoolExecutor(options.jobs) as pool:
        for line in pool.map(lambda t: scan(t, run_dir, options.timeout, extra), targets):
            print(line, flush=True)


if __name__ == "__main__":
    main()
