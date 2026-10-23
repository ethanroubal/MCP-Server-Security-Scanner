# The zoo

Known-bad MCP servers, written to test mcpiranha against attacks rather than against its own
fixtures. Each sample reconstructs an attack class or a public incident, says which rules a
correct scan must report, and `mcpiranha bench` checks that it does:

```bash
uv run mcpiranha bench                      # every sample
uv run mcpiranha bench --only rug-pull      # one sample
uv run mcpiranha bench -f json
uv run python zoo/registries/registries.py up   # first, for the supply-chain (sc-*) samples
```

Supply-chain samples look packages up, so `--offline` skips them, as does `bench` when their
local registries aren't running.

`tests/test_bench.py` runs the whole zoo, so a rule change that stops detecting a sample fails CI
(the supply-chain samples in the Docker job, against the local registries).

## Safety rules

Samples are safe by construction, which is why `bench` runs them on the host like the tests:

- **No real malware.** Every sample is written here, never downloaded. Incident reconstructions
  copy the technique (what the model is shown, or what the code does), not the original code.
- **Nothing leaves the machine.** No sample opens a network connection or writes a file. Where an
  attack would send data (a BCC address, an "audit" URL), the destination is on the reserved
  `.invalid` domain and the data stays in memory. Secrets read from the environment are the
  sandbox's dummy values.
- **Never published publicly.** Supply-chain samples are published only to local registries
  (`zoo/registries/registries.py up` starts verdaccio and pypiserver on 127.0.0.1, with no
  uplink to the public registries). Their install scripts and setup.py are inert, and nothing
  installs them: mcpiranha only reads registry metadata. Two samples look up real packages
  (`postmark-mcp`, `mcp-remote`) on the public registry and osv.dev, without downloading them.
- **Invisible characters are built at runtime** (`chr(...)`), so the source stays readable and
  `tests/test_source_hygiene.py` still passes.

## What's covered: the threat catalog

[`threats.yaml`](threats.yaml) lists every way we know a malicious MCP server can act (60 so far),
grouped by where it shows up: metadata the model reads, other servers in the same client, changes
over time, client configuration, requests the server sends the client, the supply chain, hidden
behavior in the code, runtime behavior, and attacks on the scanner itself. Each entry names the
rules that detect it and the zoo samples, fixtures or unit tests that prove it, or says why it
isn't detected yet and what will close it.

`tests/test_threat_coverage.py` keeps it honest: every rule must be in the catalog and exercised
by a test, every test it names must exist and expect its rules, and every gap must be explained.
`mcpiranha bench` ends with the catalog's state (currently 51 detected, 3 partly, 6 not yet:
tool output, dependency code, repository diffs, and runtime egress, file access and time bombs).

Vulnerable (not malicious) servers sit next to safe twins: `safe-tools` lists rules that must not
fire (`forbid:`), so a change that adds false positives fails the bench too.

Most samples run as live servers; some are config only (`connect: false`), and the source-only
ones (`reverse-shell`, `wiper`, `persistence`, ...) are never launched: their payload sits after
an early `return` in a function nothing calls, so the scanner can parse it and nothing can run it.

The OAuth half of [CVE-2025-6514](https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/)
(mcp-remote opened a server-supplied authorization URL as given) is a test of the scanner
itself: `--oauth` opens only http(s) URLs (`tests/test_connect.py`).

## Adding a sample

A directory under `samples/` with the server code and a `sample.yaml`:

```yaml
title: One line
attack: tool-poisoning          # free-form class, shown in the report
source: https://...             # the incident or write-up it reconstructs, if any
connect: true                   # false: config only, nothing launched
servers:                        # client-config entries; installed together, as one client
  name: {command: "${PYTHON}", args: ["${SAMPLE}/server.py"]}
expect: [MCP-TP-004]            # rules a correct scan must report
gap: Why it can't be detected yet, and what closes it   # instead of `expect`
lookup: true                    # supply-chain sample: look packages up on npm/PyPI and OSV
registries: {npm: "http://127.0.0.1:4873"}   # ...in these registries instead (implies lookup)
```

`bench` reports a sample as **pass** (every expected rule fired), **fail** (one didn't), **gap**
(known blind spot) or **gap-flagged** (a known gap now gets findings: review it and turn the
gap into `expect`). Rules that fire beyond `expect` are listed but don't fail the sample.

Don't tune a rule on a sample and then count that sample as evidence it works. New attacks are
worth more written by someone who hasn't read the rules: a held-out set, scored before any rule
change it prompts.
