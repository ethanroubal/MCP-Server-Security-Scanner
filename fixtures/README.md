# Fixture corpus

Intentionally malicious and benign MCP server data. It serves as the rule regression suite, the
corpus for `mcpscan bench` (Phase 2), and a demo. See docs/ARCHITECTURE.md §8.

## Layout

```
fixtures/metadata/<case>/
  snapshots.json   # a list of ServerSnapshot objects (an "inventory"; usually one server)
  expected.json    # {"description": "...", "expected_rules": ["MCP-TP-001", ...]}
```

`expected_rules` lists every rule that **should** fire on the case, including rules that don't exist
yet. `tests/test_fixtures.py` checks every registered rule against every case: a rule must fire on
the cases that list it and must stay silent on all the others. A case's not-yet-implemented rules
start being checked automatically when those rules land.

Benign cases (`benign-*`) have an empty list and catch false positives. Add a benign look-alike
whenever you add a detector.

## Invisible characters

Keep invisible characters as `\uXXXX` escapes in the JSON (surrogate pairs for code points above
U+FFFF, e.g. tag character U+E0041 is `\udb40\udc41`). Raw invisible characters in a fixture are
impossible to review. `mcpscan inspect fixtures/metadata/<case>/snapshots.json` shows what the
model sees, with hidden characters revealed.

The `ghp_FAKE…` token in `config-floating-secret` is fake.
