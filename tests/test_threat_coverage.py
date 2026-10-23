"""The threat catalog (zoo/threats.yaml) must match the rules and the tests that prove them.

Fails when a rule has no test, a catalog entry claims detection without a test that exercises
its rules, a referenced sample/fixture/test doesn't exist, or a gap isn't explained. Whether the
samples actually pass is tests/test_bench.py's job (and test_fixtures.py's for fixtures).
"""

import json
import re
import sys
from pathlib import Path
from typing import Any, cast

import pytest
import yaml

from mcpiranha import bench
from mcpiranha.rules import load_rules

ROOT = Path(__file__).parent.parent
CATALOG = cast(list[dict[str, Any]], yaml.safe_load((ROOT / "zoo" / "threats.yaml").read_text()))
SAMPLES = {s.name: s for s in bench.load_samples(ROOT / "zoo", sys.executable)}
FIXTURES = {
    p.name: set(json.loads((p / "expected.json").read_text())["expected_rules"])
    for p in (ROOT / "fixtures" / "metadata").iterdir()
    if p.is_dir()
}
OPT_IN_RULES = {"MCP-TP-010"}  # the experimental classifier, only with --classifier
RULES = {r.id for r in load_rules(plugins=False)} - OPT_IN_RULES


def _expected(test: str) -> set[str] | None:
    """Rules a zoo sample or fixture must trigger; None for unit tests (they assert directly)."""
    kind, _, name = test.partition(":")
    if kind == "zoo":  # a safe twin exercises the rules it forbids
        return set(SAMPLES[name].expect) | set(SAMPLES[name].forbid)
    if kind == "fixture":
        return FIXTURES[name]
    return None


def test_catalog_shape() -> None:
    ids = [e["id"] for e in CATALOG]
    assert len(ids) == len(set(ids)), "duplicate threat ids"
    for entry in CATALOG:
        assert entry["status"] in ("detected", "partial", "gap"), entry["id"]
        assert entry.get("title") and entry.get("surface"), entry["id"]
        if entry["status"] != "detected":
            assert entry.get("gap"), f"{entry['id']}: say why it isn't (fully) detected"
        else:
            assert entry.get("tests"), f"{entry['id']}: detected, but nothing proves it"


@pytest.mark.parametrize("entry", CATALOG, ids=lambda e: e["id"])
def test_referenced_tests_exist(entry: dict[str, Any]) -> None:
    for test in entry.get("tests", []):
        kind, _, name = test.partition(":")
        if kind == "zoo":
            assert name in SAMPLES, f"no zoo sample {name}"
        elif kind == "fixture":
            assert name in FIXTURES, f"no fixture {name}"
        elif kind == "test":
            path, _, function = name.partition("::")
            source = (ROOT / path).read_text()
            assert re.search(rf"^def {re.escape(function)}\(", source, re.M), f"no test {name}"
        else:
            raise AssertionError(f"unknown test kind in {test}")
    for rule in entry.get("rules", []):
        assert rule in RULES | OPT_IN_RULES, f"{entry['id']}: unknown rule {rule}"


@pytest.mark.parametrize("entry", CATALOG, ids=lambda e: e["id"])
def test_tests_exercise_the_rules(entry: dict[str, Any]) -> None:
    rules = set(entry.get("rules", []))
    for test in entry.get("tests", []):
        expected = _expected(test)
        if expected is None:
            continue
        if entry["status"] == "gap":
            sample = SAMPLES.get(test.partition(":")[2])
            assert sample is not None and sample.gap, f"{test}: a gap's sample must be a gap too"
        elif entry["status"] == "detected":
            assert rules <= expected, f"{test} doesn't expect {sorted(rules - expected)}"
        else:
            assert rules & expected, f"{test} expects none of {sorted(rules)}"


def test_every_rule_is_in_the_catalog_and_tested() -> None:
    cataloged = {r for e in CATALOG for r in e.get("rules", [])}
    assert RULES - cataloged == set(), "rules missing from zoo/threats.yaml"
    exercised = (
        {r for s in SAMPLES.values() for r in s.expect}
        | {r for rules in FIXTURES.values() for r in rules}
        | {  # rules whose entry is proven by a unit test (e.g. a live HTTP server)
            r
            for e in CATALOG
            if any(t.startswith("test:") for t in e.get("tests", []))
            for r in e.get("rules", [])
        }
    )
    assert RULES - exercised == set(), "rules no zoo sample, fixture or unit test exercises"


def test_every_zoo_sample_is_in_the_catalog() -> None:
    referenced = {t.partition(":")[2] for e in CATALOG for t in e.get("tests", [])
                  if t.startswith("zoo:")}  # fmt: skip
    assert set(SAMPLES) - referenced == set(), "zoo samples no threat refers to"
