# Adversarial regression tests

The test suite checks specific detection guarantees and benign controls. A passing suite
does not prove detection of every malicious server, paraphrase, program behavior or trigger.

Run the new adversarial batches without Docker or registry access:

```bash
uv run pytest -q tests/test_adversarial_matrix.py tests/test_runtime_matrix.py
```

`test_adversarial_matrix.py` places the same credential-stealing instruction on 32 surfaces:
tool/server metadata, prompt arguments, resources, input/output schemas, earlier tool
definitions and six kinds of session content. Eight disguises cover ordinary and uppercase
text, fullwidth characters, zero-width insertion, Unicode tags, variation-selector encoding,
base64 and hex. The 256 attack cases assert expected detectors, exact JSON pointers and
verbatim evidence spans. Another 128 cases put legitimate usage instructions, credential-path
mentions, hashes and emoji on the same surfaces to check false positives.

Two live stdio tests use `fixtures/servers/structured_poison.py`, an inert metadata fixture
and its clean twin. The poisoned fixture removes its payload after the first listing. Tests
check detection in the retained definition and in a saved snapshot rescanned offline; the
fixture never reads credentials or sends network traffic.

`test_runtime_matrix.py` adds 115 deterministic checks for five credential-read syscalls,
all four synthetic credential paths, decimal/hexadecimal successful reads, EOF and failed
reads, ordinary files, descriptor replacement, probe-window boundaries, incomplete probe
windows and expected versus unexpected network activity. These are trace-parser and rule
tests; they complement the existing live Docker tests and do not replace them.

Run the full suite including live Docker tracing:

```bash
MCPIRANHA_DOCKER_TESTS=1 uv run pytest -q
```

Registry-backed zoo tests additionally require `MCPIRANHA_ZOO_REGISTRIES=1` and the local
registries described in `zoo/README.md`. Classifier integration requires
`MCPIRANHA_ML_TESTS=1`, the optional ML dependencies and the downloaded model.

When adding attacks, specify the expected rule independently of scanner output, add a benign
twin, and check evidence/location as well as detection. If the scanner misses a supported
case, retain the failing regression while fixing it. For an unsupported behavior, record the
limitation in `zoo/threats.yaml`; do not weaken the expected result to make the test pass.

Remaining evaluation priorities include independent paraphrases, source flows through
callbacks/objects beyond current taint limits, and payloads gated on time, identity or call
counts. Bounded scans cannot guarantee activation of arbitrary conditional behavior.
