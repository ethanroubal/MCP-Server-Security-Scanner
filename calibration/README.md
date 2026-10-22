# Calibration

Measures how mcpscan's rules behave on real, popular MCP servers, so they can be tuned for false
positives without guessing.

```bash
uv run python calibration/build_targets.py          # rank the registry, write targets.json
uv run python calibration/run.py --run NAME         # scan every target in the Docker sandbox
uv run python calibration/report.py --run NAME      # REPORT.md + labels.yaml for review
uv run python calibration/rescan.py --from NAME --to NAME-tuned   # rerun rules offline
```

- **build_targets.py** pages the official MCP registry, keeps the latest stdio packages (npm,
  PyPI, OCI), ranks them by last-month downloads and pins the top 60/25/15 to their registry
  versions, with a client-style launch config (dummy values for required and secret env vars,
  the declared package and runtime arguments). The registry and download counts are cached in
  `.cache/`.
- **run.py** scans each target on its own, from its own directory, with `mcpscan scan
  --connect --save-snapshots`. It resumes: targets with a report are skipped.
  `--allow-network` / `--allow-install-scripts` pass the matching opt-ins through.
- **report.py** writes `results/NAME/REPORT.md` (coverage, then every finding by rule) and
  `labels.yaml` (one entry per finding, for tp / fp / unsure verdicts; kept across reruns).
- **rescan.py** reruns the current rules against a run's saved snapshots, launching nothing, so
  a rule change can be measured in seconds.

`results/` and `.cache/` are gitignored: they hold third-party server metadata.

## 2026-10 run: what changed

Target set: the 100 most-downloaded stdio servers in the registry on 2026-10-22 (60 npm,
25 PyPI, 15 OCI). Docker 29.9.1 on Apple silicon.

### False positives

| | Before tuning | After tuning |
|---|---|---|
| Tool-metadata findings (TP-*, XS-*) on listed servers | 75 on 25 servers, all false positives | **0** |
| Config findings caused by calibration's own dummy values (CF-001) | 15 | 0 |
| RP-002 / RP-003 (legitimate: mutable image tags, a `list_changed` at startup) | 16 | 18 |

No server in this set showed signs of poisoning, so the run measures false positives only;
detection is covered by the fixture corpus, which still passes in full.

What the false positives taught (and the rule changes, in the rules' docstrings):

- Popular tools give the model usage guidance ("you should always run the linter", "before
  calling this tool, read the schema"). MCP-TP-004 now separates *attack signals* (keeping
  things from the user, overriding earlier instructions, hooking other tools, sending data to an
  outside address) from guidance, and needs at least one signal. Concealment alone ("Never tell a
  user a message was scheduled") no longer reaches the threshold.
- Mentioning `.env`, the keychain or `mcp.json` is common and benign. MCP-TP-005 now needs the
  reference to be hidden, paired with model steering, or acted on in the same sentence ("read",
  "send", "upload").
- Hash fields ("SHA1 of the contents of the file"), `comment` and `environment` parameters are
  everywhere. MCP-TP-009 no longer fires on soliciting phrasing for arbitrary parameter names.
- HTML comments held example markup; indented code produced whitespace runs. MCP-TP-003 and
  MCP-TP-008 now report them only when what they hide is itself suspicious.

`fixtures/metadata/benign-calibration-2026-10` keeps all of these as a regression test.

### Coverage (servers whose tools could be listed)

| Run | Listed |
|---|---|
| First run | 52 / 100 |
| Sandbox and config fixes, default posture (no network, no install scripts) | **59 / 100** |
| Plus `--allow-network --allow-install-scripts` | 62 / 100 |

Fixes that came out of it: a writable working directory for package servers, a writable root for
image servers, a Python 3.13 fallback (uv's wrapped error text broke the first attempt), an
amd64 fallback for images without an ARM build, console-script lookup for PyPI packages whose
executable isn't named like the package, `uvx --with` support, and better registry-derived
configs (subcommands given as hints, runtime arguments, optional secrets but not connection
strings).

The remaining 38 mostly can't be listed without information the registry doesn't carry: real
credentials or service URLs validated at startup, subcommands or arguments the registry entry
omits, packages broken against `mcp` 2.x, or servers that crash in any environment.
