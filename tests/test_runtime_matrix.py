"""Behavioral evidence: read variants, negative controls, and temporal attribution limits."""

from datetime import UTC, datetime, timedelta

import pytest

from mcpiranha.core.models import DynamicObservation, ProbeRun, Severity
from mcpiranha.core.pipeline import scan
from mcpiranha.dynamic.constants import HONEYTOKENS
from mcpiranha.dynamic.trace import correlate, observations
from mcpiranha.rules import load_rules
from tests.helpers import snapshot_with_description

RULES = load_rules(plugins=False)
READS = {
    "read": "read(0x3, 0xdeadbeef, 0x100)",
    "pread64": "pread64(0x3, 0xdeadbeef, 0x100, 0)",
    "readv": "readv(0x3, 0xdeadbeef, 0x2)",
    "preadv": "preadv(0x3, 0xdeadbeef, 0x2, 0)",
    "preadv2": "preadv2(0x3, 0xdeadbeef, 0x2, 0, 0)",
}


@pytest.mark.parametrize("path", sorted(HONEYTOKENS))
@pytest.mark.parametrize("operation", READS)
@pytest.mark.parametrize("returned", ["0x10", "16", "0", "-1 EAGAIN (Try again)"])
def test_credential_read_variants_and_non_reads(path: str, operation: str, returned: str) -> None:
    events = observations(
        f'1 1800000000.001 open("{path}", O_RDONLY) = 3\n'
        f"1 1800000000.002 {READS[operation]} = {returned}",
        [],
    )
    accesses = [e for e in events if e.kind == "file_access"]
    positive = returned in ("0x10", "16")
    assert len(accesses) == int(positive)
    if positive:
        assert accesses[0].byte_count == 16
        assert accesses[0].honeytoken == path
    snapshot = snapshot_with_description("Weather.").model_copy(update={"observations": events})
    findings = [f for f in scan([snapshot], RULES).findings if f.rule_id == "MCP-DY-003"]
    assert len(findings) == 1
    assert ("read 16 byte(s)" in findings[0].rationale) == positive
    assert ("opened" in findings[0].rationale) != positive
    assert "0xdeadbeef" not in findings[0].rationale


@pytest.mark.parametrize("path", ["/tmp/ordinary", "/tmp/mcpiranha-home/.ssh/id_rsa.backup"])
@pytest.mark.parametrize("operation", READS)
def test_ordinary_files_are_not_synthetic_credentials(path: str, operation: str) -> None:
    events = observations(
        f'1 1800000000.001 open("{path}", O_RDONLY) = 3\n'
        f"1 1800000000.002 {READS[operation]} = 0x10",
        [],
    )
    snapshot = snapshot_with_description("Weather.").model_copy(update={"observations": events})
    assert not [f for f in scan([snapshot], RULES).findings if f.rule_id == "MCP-DY-003"]


@pytest.mark.parametrize(
    "transition",
    [
        "close(3) = 0",
        'open("/tmp/ordinary", O_RDONLY) = 3',
        "dup2(9, 3) = 3",  # untracked descriptor replaces a credential descriptor
    ],
)
@pytest.mark.parametrize("operation", READS)
def test_descriptor_replacement_cannot_reuse_stale_identity(
    transition: str, operation: str
) -> None:
    events = observations(
        '1 1800000000.001 open("/tmp/mcpiranha-home/.env", O_RDONLY) = 3\n'
        f"1 1800000000.002 {transition}\n"
        f"1 1800000000.003 {READS[operation]} = 0x10",
        [],
    )
    assert not [e for e in events if e.kind == "file_access"]


@pytest.mark.parametrize(
    "offset,associated", [(-1, False), (0, True), (1, True), (2, True), (3, False)]
)
def test_probe_time_boundaries_do_not_attribute_background_activity(
    offset: int, associated: bool
) -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    probe = ProbeRun(
        id="probe",
        tool="lookup",
        variant="ssrf",
        started_at=start,
        finished_at=start + timedelta(seconds=2),
        status="completed",
    )
    event = DynamicObservation(
        kind="net_connect",
        phase="listing",
        detail="test",
        at=start + timedelta(seconds=offset),
        destination="192.0.2.1:80",
    )
    [correlated] = correlate([event], [probe])
    assert (correlated.probe_id == probe.id) == associated
    assert (correlated.tool == "lookup") == associated
    result = scan(
        [
            snapshot_with_description("Weather.").model_copy(
                update={"probes": [probe], "observations": [correlated]}
            )
        ],
        RULES,
    )
    assert any(f.rule_id == "MCP-DY-006" for f in result.findings) == associated
    assert event.probe_id is None  # never mutate the original observation


@pytest.mark.parametrize("missing", ["event-time", "probe-end", "different-probe", "baseline"])
def test_incomplete_or_unrelated_probes_do_not_prove_a_canary_hit(missing: str) -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    probe = ProbeRun(
        id="probe",
        tool="lookup",
        variant="ssrf",
        started_at=start,
        finished_at=start + timedelta(seconds=2),
        status="completed",
    )
    event = DynamicObservation(
        kind="net_connect",
        phase="listing",
        detail="test",
        at=start + timedelta(seconds=1),
        destination="192.0.2.1:80",
    )
    if missing == "event-time":
        event.at = None
    elif missing == "probe-end":
        probe.finished_at = None
    elif missing == "different-probe":
        probe.id = "different"
        event.probe_id = "probe"
        event.at = None
    else:
        probe.variant = "baseline"
    result = scan(
        [
            snapshot_with_description("Weather.").model_copy(
                update={"probes": [probe], "observations": correlate([event], [probe])}
            )
        ],
        RULES,
    )
    assert not [f for f in result.findings if f.rule_id == "MCP-DY-006"]


def test_expected_network_activity_stays_visible_beside_unexpected_activity() -> None:
    events = [
        DynamicObservation(
            kind="net_connect",
            phase="invocation",
            detail="approved API",
            destination="api.example.invalid:443",
            expected=True,
        ),
        DynamicObservation(
            kind="net_connect",
            phase="invocation",
            detail="unknown port",
            destination="api.example.invalid:444",
            expected=False,
        ),
    ]
    result = scan(
        [snapshot_with_description("Weather.").model_copy(update={"observations": events})], RULES
    )
    findings = [f for f in result.findings if f.rule_id == "MCP-DY-004"]
    assert {f.severity for f in findings} == {Severity.INFO, Severity.MEDIUM}
    assert any("unknown port" in f.rationale and f.severity is Severity.MEDIUM for f in findings)
