# mcpscan

Security scanner for Model Context Protocol (MCP) servers: tool poisoning, cross-server shadowing,
rug pulls, insecure configuration, vulnerable implementations and dangerous combinations of servers.
It works fully offline; bringing your own LLM is optional. Design: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

**Status: Phase 0.** Scans snapshot JSON files with one rule so far (MCP-TP-001, invisible/smuggled
Unicode). See [docs/RULES.md](docs/RULES.md) for the catalog.

## Development

```bash
uv sync
uv run mcpscan scan fixtures/metadata/unicode-tag-smuggling/snapshots.json
uv run mcpscan inspect fixtures/metadata/unicode-tag-smuggling/snapshots.json
uv run pytest
uv run ruff check . && uv run ruff format --check . && uv run pyright
```

## Adding a rule

1. Reserve an id in `docs/RULES.md`.
2. Add a module under `src/mcpscan/rules/builtin/` with a `Rule` subclass decorated with
   `@register` (see `invisible_unicode.py`). Iterate text with `iter_text_fields` so nested schema
   text is covered.
3. List the id in `expected.json` for each fixture case it should fire on, and add a benign
   look-alike case. `tests/test_fixtures.py` then checks it everywhere.

Third-party rule packs can register through the `mcpscan.rules` entry-point group.
