"""Score distributions for the local classifier: real servers (benign) vs the attack fixtures.

Usage: uv run --extra ml python calibration/classifier_scores.py --run 2026-10-22-v2

Benign: every text field (24+ characters) in the run's saved snapshots of servers that listed.
Attacks: per fixture case that expects a tool-poisoning rule, the highest-scoring field.
Prints how many of each clear a range of thresholds, to choose THRESHOLD in classifier/rule.py.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from mcpscan.classifier import load
from mcpscan.classifier.rule import MIN_CHARS
from mcpscan.core.io import load_snapshots
from mcpscan.core.text import iter_text_fields

HERE = Path(__file__).parent
FIXTURES = HERE.parent / "fixtures" / "metadata"
THRESHOLDS = (0.5, 0.9, 0.99, 0.995, 0.999, 0.9999)


def texts(path: Path) -> list[str]:
    return [tf.text for s in load_snapshots(path) if s.tools_listed for tf in iter_text_fields(s)
            if tf.kind not in ("name", "uri", "property-name")
            and len(tf.text.strip()) >= MIN_CHARS]  # fmt: skip


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run", required=True)
    options = parser.parse_args()
    classifier = load(progress=print)

    benign: list[tuple[float, str, str]] = []
    for path in sorted((HERE / "results" / options.run / "snapshots").glob("*.json")):
        fields = texts(path)
        for text, score in zip(fields, classifier.score(fields), strict=True):
            benign.append((score.probability, path.stem, text[score.start : score.end]))

    attacks: list[tuple[float, str]] = []
    for case in sorted(p for p in FIXTURES.iterdir() if p.is_dir()):
        expected = json.loads((case / "expected.json").read_text())["expected_rules"]
        fields = texts(case / "snapshots.json")
        if not fields or not any(r.startswith("MCP-TP") for r in expected):
            continue
        attacks.append((max(s.probability for s in classifier.score(fields)), case.name))

    print(f"benign fields: {len(benign)}, attack cases: {len(attacks)}")
    print(f"{'threshold':>10} {'benign >= t':>12} {'attacks >= t':>13}")
    for t in THRESHOLDS:
        b = sum(p >= t for p, _, _ in benign)
        a = sum(p >= t for p, _ in attacks)
        print(f"{t:>10} {b:>12} {f'{a}/{len(attacks)}':>13}")
    print("\nattack cases:")
    for p, name in sorted(attacks):
        print(f"  {p:.5f}  {name}")
    print("\nhighest-scoring benign fields:")
    for p, server, text in sorted(benign, reverse=True)[:12]:
        print(f"  {p:.5f}  {server}: {' '.join(text.split())[:140]}")


if __name__ == "__main__":
    main()
