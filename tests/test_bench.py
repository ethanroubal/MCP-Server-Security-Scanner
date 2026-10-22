"""The zoo (zoo/samples) as a regression suite: every sample must still be detected.

Supply-chain samples need registry lookups, so they're skipped here unless
MCPIRANHA_ZOO_REGISTRIES=1: then the zoo's local registries must be running
(zoo/registries/registries.py up), and the public npm registry and osv.dev reachable.
"""

import os
import sys
from pathlib import Path

import anyio
import pytest

from mcpiranha import bench
from mcpiranha.rules import load_rules

ZOO = Path(__file__).parent.parent / "zoo"


def _run(lookup: bool) -> list[bench.SampleResult]:
    samples = bench.load_samples(ZOO, sys.executable)
    assert len(samples) >= 18
    return anyio.run(lambda: bench.run(samples, load_rules(plugins=False), jobs=8, lookup=lookup))


def test_every_zoo_sample_is_detected_or_a_known_gap() -> None:
    results = _run(lookup=False)
    report = {r.sample.name: (r.status, sorted(r.missing), r.errors) for r in results}
    assert all(r.status in ("pass", "gap") or r.sample.lookup for r in results), report
    assert all(r.status == "skipped" for r in results if r.sample.lookup), report


@pytest.mark.skipif(
    os.environ.get("MCPIRANHA_ZOO_REGISTRIES") != "1",
    reason="set MCPIRANHA_ZOO_REGISTRIES=1 (needs the zoo registries and network)",
)
def test_supply_chain_samples_against_the_registries() -> None:
    results = [r for r in _run(lookup=True) if r.sample.lookup]
    report = {r.sample.name: (r.status, sorted(r.missing), r.errors, r.skipped) for r in results}
    assert results and all(r.status == "pass" for r in results), report


def test_samples_must_say_what_they_expect(tmp_path: Path) -> None:
    (tmp_path / "sample.yaml").write_text("servers: {a: {command: x}}\n")
    with pytest.raises(bench.SampleError, match="expect"):
        bench.load_samples(tmp_path, sys.executable)
    (tmp_path / "sample.yaml").write_text("servers: {a: {command: x}}\nexpect: []\ngap: later\n")
    [sample] = bench.load_samples(tmp_path, sys.executable)
    assert sample.gap == "later"


def test_placeholders_are_substituted(tmp_path: Path) -> None:
    (tmp_path / "sample.yaml").write_text(
        'servers: {a: {command: "${PYTHON}", args: ["${SAMPLE}/s.py", "${OTHER}"]}}\n'
        "expect: [MCP-TP-001]\n"
    )
    [sample] = bench.load_samples(tmp_path, "/usr/bin/python3")
    assert sample.servers["a"] == {"command": "/usr/bin/python3",
                                   "args": [f"{tmp_path}/s.py", "${OTHER}"]}  # fmt: skip
