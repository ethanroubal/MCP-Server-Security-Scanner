# Calibration

Measures how mcpiranha's rules behave on real, popular MCP servers, so they can be tuned for false
positives without guessing.

```bash
uv run python calibration/build_targets.py          # rank the registry, write targets.json
uv run python calibration/run.py --run NAME         # scan every target in the Docker sandbox
uv run python calibration/report.py --run NAME      # REPORT.md + labels.yaml for review
uv run python calibration/rescan.py --from NAME --to NAME-tuned   # rerun rules offline
uv run python calibration/flows_review.py --run NAME   # cross-server flows on combined servers
uv run python calibration/supply_review.py [--unpinned] [--source]  # MCP-SC (+ MCP-SRC) rules
```

- **build_targets.py** pages the official MCP registry, keeps the latest stdio packages (npm,
  PyPI, OCI), ranks them by last-month downloads and pins the top 60/25/15 to their registry
  versions, with a client-style launch config (dummy values for required and secret env vars,
  the declared package and runtime arguments). The registry and download counts are cached in
  `.cache/`.
- **run.py** scans each target on its own, from its own directory, with `mcpiranha scan
  --connect --save-snapshots`. It resumes: targets with a report are skipped.
  `--allow-network` / `--allow-install-scripts` pass the matching opt-ins through.
- **report.py** writes `results/NAME/REPORT.md` (coverage, then every finding by rule) and
  `labels.yaml` (one entry per finding, for tp / fp / unsure verdicts; kept across reruns).
- **flows_review.py** puts a run's saved snapshots into one client, as if installed together:
  a handful of realistic setups, then 1,000 random three-server ones for the base rate.
- **supply_review.py** looks every npm/PyPI target up on the registries and osv.dev and runs
  the MCP-SC rules, launching nothing; `--unpinned` drops the versions, as most configs do.
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

## 2026-10 run: toxic flows and the classifier

`rescan.py` against the same snapshots (each server scanned alone, so these are single-server
flows; cross-server flows only exist across a client's servers):

- **Capability labels** from tool names first over-labelled: `openWorldHint` / `destructiveHint`
  are set loosely by real servers, "fetch" and "request" are generic verbs, and nouns like
  "notebook" or "commands" don't mean code runs. Fixing those (tests in `tests/test_flows.py`)
  cut MCP-TF-002 from 24 servers to 12.
- **What remains** is mostly real and by design: GitLab reading issues and files and opening
  merge requests, mail and chat servers that read and send (MCP-TF-001, 13 servers, medium);
  browser servers that also evaluate JavaScript (MCP-TF-002, 12 servers, low). A few are
  name-based guesses (console messages counted as untrusted input).

**Classifier** (`classifier_scores.py` and the variants it led to). Off the shelf, the model
can't separate tool metadata from attacks:

| Applied to | Benign fields flagged (of 59 servers' text) | Attack fixtures | Reworded attacks the rules miss |
|---|---|---|---|
| All text fields, raw, p >= 0.99 | 1,111 | 4 / 10 | 1 / 3 |
| Descriptions only, 80+ chars, p >= 0.99 | 426 | 5 / 10 | 1 / 3 |
| Sentences addressed to the model, p >= 0.999 (shipped) | 210 (24 servers) | 4 / 10 | 2 / 3 |

It was trained on chat prompts to flag text that instructs an LLM, and MCP descriptions instruct
the LLM by design ("MUST ask the user in the language they are using"). Hidden-text attacks score
near zero until decoded. So `--classifier` ships as an experimental, low-severity review queue.
The fix is a model fine-tuned on MCP metadata: these snapshots are the benign half of that
training set.

## 2026-10 run: cross-server flows

Calibration scans each server alone, so `flows_review.py` combined the 59 listed servers into
setups people plausibly run (GitLab + Desktop Commander + Chrome DevTools, Microsoft 365 +
Google Workspace, MongoDB + ClickHouse + Airtable + Tavily, SearXNG + Desktop Commander, ...).

- **Chains were mostly right in shape but often picked a wrong step.** Fixed (each has a test in
  `tests/test_flows.py`): "forward" in `go_forward` and "post" in `read_post` counted as sending;
  mail folders, rules and drafts counted as outbound (`send-draft-message` still does); OneNote
  and Slides "pages" counted as web pages and `get-download-url` as a fetch; `read_resource(uri)`
  as a request to any URL; names ending in metadata (`get_file_info`, `list_tables`,
  `list-mail-folders`) as private data; `select_page` as a read; stopping a process
  (`force_terminate`, `kill_process`) and `browser_drop` (drag and drop) as destroying data;
  `evaluate_reconstruction_coverage` as running code. Running a SQL query now counts as reading
  private data. Labelled tools went from 73 to 60 (outbound), 89 to 70 (untrusted input), 141 to
  123 (private data), 24 to 21 (code) and 59 to 55 (destructive).
- **A read-only set (Context7, Repomix, Nx, Figma) has no flows**; every other realistic setup
  has a high MCP-TF-001 or TF-002, with chains that read correctly, e.g. `gitlab.get_issue ->
  desktop-commander.list_directory -> chrome-devtools.navigate_page` and `searxng_web_search ->
  desktop-commander.start_process`.
- **Base rate: 54% of random three-server setups get a high MCP-TF-001, 42% a high TF-002**
  (57% / 43% before the fixes). That is mostly real rather than noise: of the 59 servers, 24
  take in untrusted content, 27 read private data, 20 can send data out and 15 run code, so
  three random popular servers usually complete the trifecta. The finding still separates
  setups (a read-only or single-purpose set doesn't fire), and the chain says which server to
  move to another client.
- **Weakest leg: outbound writes into the user's own service** (an Airtable comment, a Sentry
  issue update). They only leak to an attacker who can read that service, which names can't
  tell; a public GitLab issue can. They are kept as outbound, and the chain shows which step it
  is. Single-server results after the fixes: MCP-TF-001 on 12 servers (medium), TF-002 on 13
  (low).

## 2026-10 run: supply chain (MCP-SC)

`supply_review.py` on the 85 npm/PyPI targets, at their pinned registry versions and unpinned
(the newest release, what `npx -y pkg` runs):

| Rule | Pinned | Unpinned | What fired |
|---|---|---|---|
| SC-001 vulnerability / malware | 1 | 0 | `praisonai` 2.3.42: 159 advisories, several critical (fixed in 4.x) |
| SC-002 install scripts | 5 | 5 | postinstall in `@azure/mcp`, `snyk`, Desktop Commander (install tracking), `@gitkraken/gk`, `claude-flow` / `loki-mode`; all present before, so low |
| SC-003 provenance | 0 | 0 | after one fix, below |
| SC-004 new package | 1 | 1 | `attestari-mcp`, 17 days old |
| SC-005 new publisher | 0 | 0 | |
| SC-006 deprecated / yanked / missing | 4 | 3 | Dynatrace and Railway deprecated; `unifi-network-mcp` 0.7.8 yanked ("install fails"); `start-mcp-server` |

- **`start-mcp-server` is a real finding.** Serena's registry entry runs `uvx -p 3.13
  start-mcp-server ... serena-agent==1.5.3`: uvx treats `start-mcp-server` as the package, and
  no such PyPI project exists. Anyone could register it, and every copy of that config would run
  their code. Missing names are therefore high.
- **Fixed during calibration** (tests in `tests/test_supply.py`): an exact pin of a yanked PyPI
  release didn't resolve (uv installs it; it's now reported instead); a PyPI project with no
  version given resolved to a prerelease; a repository renamed by the same owner
  (`sirkirby/unifi-network-mcp` to `sirkirby/unifi-mcp`) counted as a provenance change, so
  SC-003 now compares owners; OSV advisories were listed in full (159), now the worst five.
- **Dropped: "release under 2 days old".** Unpinned, it fired on 31 of 84 servers: popular MCP
  servers release almost daily, so the age of the newest release says nothing. Package age stays.
- **What isn't covered:** dependencies (their install scripts and advisories, which `npx` also
  runs), Docker images, and PyPI publisher changes beyond provenance (PyPI's API doesn't say who
  uploaded a release). SC-003 and SC-005 fired on nothing real; the zoo's hijack samples are
  their only positive evidence so far.

## 2026-10 run: source analysis (MCP-SRC)

`supply_review.py --source` downloads each target's release archive (84 of 85; one name doesn't
exist), checks it against the registry's hash and analyzes it in memory: 15,848 files at the
pinned versions, 19,000 at the newest releases. Seven files over 5 MB (bundles) were skipped.

First pass, before tuning: SRC-001 (fixed Bcc/Cc), SRC-002, SRC-004's decoded-code half and
SRC-005 (request catchers) found nothing. Two detectors were all noise:

- **`curl ... | sh` strings: 8 packages, all benign**: install instructions printed to the user
  (uv, CLIs), and security tools' deny-lists of dangerous commands. Dropped.
- **Credential paths: 13 packages, all benign**: dbhub's SSH tunnel reads `~/.ssh/id_rsa` by
  default, scanners list `.npmrc` / `.aws/credentials` to block them, `.npmrc` is read for the
  registry URL. SRC-003 now needs the same code to also have a way out (a fixed recipient, a
  request catcher, or an environment harvest): that pair is what a stealer looks like.
- **Then, on the newest releases**, bernstein's `doctor` command listed which `API` / `TOKEN`
  variables are set (names only, for a report). SRC-002 now needs the values read
  (`.items()`, `environ[k]`, `Object.entries`, `process.env[k]`).

After tuning: **no MCP-SRC findings on any of the 84 packages**, pinned or newest, while the zoo's
five source samples (local scripts, an npm tarball and a wheel) are all detected. What isn't
covered: dependencies' code, files over 5 MB, Docker images, and anything needing data flow
(where a tool's arguments end up), which is the next step.

## Typosquat targets (MCP-XS-003)

`update_known_packages.py` builds the list of names typosquatters would imitate from the
registry's most-downloaded packages plus curated well-known ones (the reference servers aren't
all in the registry), then measures it against every registry package, nearly all of which are
legitimate. Whole-name edit distance flagged unrelated short names (`kiwi-mcp` / `kibi-mcp`,
`@x/agent` / `@swmansion/argent`), so the rule now matches the shapes typosquats actually take:
an unscoped near-miss of an unscoped name, the same package under a near-miss scope, an unscoped
package named after a known publisher, or a popular unscoped name republished under another scope.
Result: 31 of 15,707 registry packages flagged (0.2%), mostly forks republished under personal
scopes, which are reported at medium ("not the package people mean; check the publisher"); true
near-misses (`kobsidian-mcp`, `dea-agents`) stay high.
