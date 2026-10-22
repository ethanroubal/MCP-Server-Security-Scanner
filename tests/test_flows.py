from pathlib import Path

import pytest

from mcpiranha.core.io import load_snapshots
from mcpiranha.core.models import CapabilityLabel, ClientSettings, Severity, ToolDef
from mcpiranha.core.pipeline import scan
from mcpiranha.flows import label_tool, words
from mcpiranha.rules import load_rules

FIXTURES = Path(__file__).parent.parent / "fixtures" / "metadata"
FLOW_RULES = [r for r in load_rules(plugins=False) if r.id.startswith("MCP-TF")]
L = CapabilityLabel
NONE: set[CapabilityLabel] = set()


def test_words() -> None:
    assert words("browserNavigate") == ["browser", "navigate"]
    assert words("slack.post-message") == ["slack", "post", "message"]
    assert words("get_PR_comments") == ["get", "pr", "comments"]


@pytest.mark.parametrize(
    ("name", "params", "expected"),
    [
        ("get_issue", {}, {L.INGESTS_UNTRUSTED_CONTENT}),
        ("read_file", {}, {L.READS_PRIVATE_DATA}),
        ("send_message", {}, {L.EXTERNAL_COMMUNICATION}),
        ("fetch", {"url": {}}, {L.INGESTS_UNTRUSTED_CONTENT, L.EXTERNAL_COMMUNICATION}),
        ("fetch", {}, {L.INGESTS_UNTRUSTED_CONTENT}),  # no URL parameter: not outbound
        ("run_command", {}, {L.EXECUTES_CODE}),
        ("delete_branch", {}, {L.DESTRUCTIVE}),
        ("write_file", {}, {L.WRITES_FILES}),
        ("get_forecast", {}, NONE),
        ("search_docs", {}, NONE),
        ("add", {}, NONE),
    ],
)
def test_label_tool(name: str, params: dict[str, object], expected: set[L]) -> None:
    assert set(label_tool(ToolDef(name=name, input_schema={"properties": params}))) == expected


def test_generic_names_are_not_over_labelled() -> None:
    # all seen mislabelled in calibration (calibration/README.md)
    names = ["create_merge_request", "create-focused-inbox-override", "create-onenote-notebook",
             "addPercySnapshotCommands", "browser_click"]  # fmt: skip
    for name in names:
        hints = {"destructiveHint": True, "openWorldHint": True}
        assert label_tool(ToolDef(name=name, annotations=hints)) == {}, name
    assert set(label_tool(ToolDef(name="run_python_script"))) == {L.EXECUTES_CODE}


def _flows(case: str, **settings: object):
    snapshots = load_snapshots(FIXTURES / case / "snapshots.json")
    if settings:
        snapshots = [s.model_copy(update={"client_settings": ClientSettings.model_validate(
            settings)}) if s.name == "chat" else s for s in snapshots]  # fmt: skip
    return scan(snapshots, FLOW_RULES).findings


def test_trifecta_is_reported_once_with_the_chain() -> None:
    [finding] = _flows("toxic-trifecta")
    assert finding.severity is Severity.HIGH
    assert finding.location.server_id == "fx-toxic-trifecta-tracker"  # the untrusted-input server
    assert "tracker.get_issue" in finding.rationale and "chat.send_message" in finding.rationale


def test_auto_approved_outbound_tool_makes_it_critical() -> None:
    [finding] = _flows("toxic-trifecta", auto_approve=["send_message"])
    assert finding.severity is Severity.CRITICAL
    assert "Auto-approved" in finding.rationale


def test_disabled_tool_breaks_the_chain() -> None:
    assert _flows("toxic-trifecta", disabled_tools=["send_message"]) == []


def test_single_server_flows_are_lower_severity() -> None:
    from mcpiranha.core.models import Origin, ServerSnapshot

    github_like = ServerSnapshot(
        id="one", name="hub", origin=Origin(kind="snapshot", ref="x"),
        tools=[ToolDef(name="get_issue"), ToolDef(name="get_file_contents"),
               ToolDef(name="create_issue_comment")],
    )  # fmt: skip
    [finding] = scan([github_like], FLOW_RULES).findings
    assert finding.severity is Severity.MEDIUM and "within one server" in finding.rationale


def test_known_servers_flow_from_config_alone() -> None:
    findings = _flows("benign-pinned-config")  # github + fetch, never connected
    assert [f.rule_id for f in findings] == ["MCP-TF-001"]
    assert "table of well-known servers" in findings[0].rationale
