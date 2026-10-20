"""Every registered rule against every fixture case: fire exactly where expected.json says."""

import json
from pathlib import Path

import pytest

from mcpscan.core.io import load_snapshots
from mcpscan.core.pipeline import scan
from mcpscan.rules import Rule, load_rules
from mcpscan.rules.base import RULE_ID_PATTERN

FIXTURES = Path(__file__).parent.parent / "fixtures" / "metadata"
CASES = sorted(p for p in FIXTURES.iterdir() if p.is_dir())
RULES = load_rules(plugins=False)


def _expected(case: Path) -> set[str]:
    return set(json.loads((case / "expected.json").read_text(encoding="utf-8"))["expected_rules"])


def test_corpus_is_not_empty() -> None:
    assert CASES
    assert any(not _expected(c) for c in CASES), "need at least one benign case"


@pytest.mark.parametrize("case", CASES, ids=lambda p: p.name)
def test_fixture_is_well_formed(case: Path) -> None:
    assert load_snapshots(case / "snapshots.json")
    for rule_id in _expected(case):
        assert RULE_ID_PATTERN.match(rule_id), f"bad rule id {rule_id!r}"


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
@pytest.mark.parametrize("case", CASES, ids=lambda p: p.name)
def test_rule_on_fixture(case: Path, rule: Rule) -> None:
    result = scan(load_snapshots(case / "snapshots.json"), [rule])
    assert not result.errors
    fired = rule.id in {f.rule_id for f in result.findings}
    should_fire = rule.id in _expected(case)
    assert fired == should_fire, (
        f"{rule.id} {'fired' if fired else 'did not fire'} on {case.name}; "
        f"expected it {'to' if should_fire else 'not to'}. Findings: "
        + "; ".join(f.rationale for f in result.findings)
    )
