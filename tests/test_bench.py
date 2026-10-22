"""The zoo (zoo/samples) as a regression suite: every sample must still be detected."""

import sys
from pathlib import Path

import anyio
import pytest

from mcpiranha import bench
from mcpiranha.rules import load_rules

ZOO = Path(__file__).parent.parent / "zoo"


def test_every_zoo_sample_is_detected_or_a_known_gap() -> None:
    samples = bench.load_samples(ZOO, sys.executable)
    assert len(samples) >= 13
    results = anyio.run(lambda: bench.run(samples, load_rules(plugins=False), jobs=8))
    report = {r.sample.name: (r.status, sorted(r.missing), r.errors) for r in results}
    assert all(r.status in ("pass", "gap") for r in results), report


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
