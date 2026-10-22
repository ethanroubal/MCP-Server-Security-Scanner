"""Core data model.

`ServerSnapshot` is the intermediate representation every analyzer consumes; `Finding` is what every
analyzer emits. See docs/ARCHITECTURE.md §4.

Two kinds of model live here:

- MCP wire objects (`ToolDef`, `PromptDef`, ...) keep the server's camelCase keys and any unknown
  fields, because attackers hide payloads in fields a typed model would otherwise drop.
- mcpiranha's own objects use snake_case and reject unknown fields, so typos in fixtures and config
  fail loudly.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr
from pydantic.alias_generators import to_camel

from mcpiranha.core.hashing import hash_json

# --- Enumerations ---------------------------------------------------------------------------------


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Higher is worse; use for sorting and threshold comparisons."""
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Detector(StrEnum):
    RULE = "rule"
    CLASSIFIER = "classifier"
    LLM = "llm"
    DYNAMIC = "dynamic"
    SUPPLY_CHAIN = "supply-chain"
    FLOW = "flow"


class Category(StrEnum):
    """Threat categories, matching the rule-id prefixes in docs/RULES.md."""

    TOOL_POISONING = "tool-poisoning"  # MCP-TP
    CROSS_SERVER = "cross-server"  # MCP-XS
    RUG_PULL = "rug-pull"  # MCP-RP
    CONFIG = "config"  # MCP-CF
    SOURCE = "source"  # MCP-SRC
    SUPPLY_CHAIN = "supply-chain"  # MCP-SC
    TOXIC_FLOW = "toxic-flow"  # MCP-TF
    DYNAMIC = "dynamic"  # MCP-DY


class CapabilityLabel(StrEnum):
    READS_PRIVATE_DATA = "reads_private_data"
    INGESTS_UNTRUSTED_CONTENT = "ingests_untrusted_content"
    EXTERNAL_COMMUNICATION = "external_communication"
    WRITES_FILES = "writes_files"
    EXECUTES_CODE = "executes_code"
    DESTRUCTIVE = "destructive"
    CREDENTIAL_ACCESS = "credential_access"
    FINANCIAL = "financial"


# --- MCP wire objects -----------------------------------------------------------------------------


class McpWireModel(BaseModel):
    """An object stored exactly as the MCP server sent it: camelCase keys, unknown fields kept."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, extra="allow")

    def wire_dump(self) -> dict[str, Any]:
        """The object as it appeared on the wire (camelCase, extras included, nulls dropped)."""
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


class ServerInfo(McpWireModel):
    name: str
    version: str | None = None
    title: str | None = None
    instructions: str | None = None  # from InitializeResult; shown to the model by many clients


class ToolDef(McpWireModel):
    name: str
    title: str | None = None
    description: str | None = None
    input_schema: dict[str, Any] = Field(default_factory=dict[str, Any])
    output_schema: dict[str, Any] | None = None
    annotations: dict[str, Any] | None = None  # recorded, never trusted (e.g. readOnlyHint)


class PromptArgument(McpWireModel):
    name: str
    title: str | None = None
    description: str | None = None
    required: bool | None = None


class PromptDef(McpWireModel):
    name: str
    title: str | None = None
    description: str | None = None
    arguments: list[PromptArgument] = []


class ResourceDef(McpWireModel):
    uri: str
    name: str
    title: str | None = None
    description: str | None = None
    mime_type: str | None = None


# --- mcpiranha objects ----------------------------------------------------------------------------


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Origin(StrictModel):
    kind: Literal["config", "npm", "pypi", "docker", "git", "path", "remote", "snapshot"]
    client: str | None = None  # "claude-desktop", "cursor", ...
    config_path: str | None = None
    ref: str  # package@version, URL, path


class Launch(StrictModel):
    transport: Literal["stdio", "http", "sse"]
    command: str | None = None
    args: list[str] = []
    env: dict[str, SecretStr] = {}  # serialized as "**********"; never rendered in reports
    url: str | None = None
    headers: dict[str, SecretStr] = {}


class ClientSettings(StrictModel):
    """Security-relevant settings the client config attaches to a server entry."""

    disabled: bool = False  # the client won't start it
    auto_approve: list[str] = []  # tools the client calls without asking the user
    auto_approve_all: bool = False  # e.g. Gemini CLI "trust": true, Kiro autoApprove ["*"]
    disabled_tools: list[str] = []


class SourceTree(StrictModel):
    root: str
    language: Literal["py", "ts", "js", "go", "other"]
    entrypoints: list[str] = []


class PackageMeta(StrictModel):
    registry: Literal["npm", "pypi", "docker"]
    name: str
    version: str | None = None  # None = floating / unpinned
    integrity: str | None = None
    install_scripts: list[str] = []
    published_at: datetime | None = None
    maintainers: list[str] = []


class DynamicObservation(StrictModel):
    kind: Literal[
        "file_open",
        "net_connect",
        "dns_lookup",
        "process_spawn",
        "tools_changed",  # tool list differed between two tools/list calls, or list_changed sent
        "auth_not_required",  # a remote server answered without any credentials
    ]
    phase: Literal["startup", "listing", "invocation"]
    detail: str
    at: datetime | None = None


class Hashes(StrictModel):
    tools: dict[str, str]  # tool name -> sha256 of its canonical wire JSON
    manifest: str  # sha256 over server info, tools, prompts and resources


class ServerSnapshot(StrictModel):
    id: str  # stable: hash of origin + name
    name: str
    origin: Origin
    launch: Launch | None = None
    client_settings: ClientSettings | None = None
    server_info: ServerInfo | None = None
    # False when the server was only read from a config file and never asked for its tools, so
    # an empty `tools` list means "unknown", not "none".
    tools_listed: bool = True
    tools: list[ToolDef] = []  # as last served
    # Earlier versions of tools that changed or disappeared while connected (a rug pull):
    # scanned too, since a client may have shown or used them.
    earlier_tools: list[ToolDef] = []
    prompts: list[PromptDef] = []
    resources: list[ResourceDef] = []
    source: SourceTree | None = None
    package: PackageMeta | None = None
    observations: list[DynamicObservation] = []

    def hashes(self) -> Hashes:
        """Computed on demand rather than stored, so it can never go stale."""
        tools = [t.wire_dump() for t in self.tools]
        return Hashes(
            tools={t["name"]: hash_json(t) for t in tools},
            manifest=hash_json(
                {
                    "serverInfo": self.server_info.wire_dump() if self.server_info else None,
                    "tools": tools,
                    "prompts": [p.wire_dump() for p in self.prompts],
                    "resources": [r.wire_dump() for r in self.resources],
                }
            ),
        )


class Location(StrictModel):
    server_id: str
    tool: str | None = None
    prompt: str | None = None
    resource: str | None = None
    json_pointer: str | None = None  # RFC 6901 pointer into the snapshot, e.g. /tools/0/description
    file: str | None = None
    line: int | None = None


class Evidence(StrictModel):
    text: str  # must exist verbatim in the analyzed content
    start: int | None = None
    end: int | None = None


class Finding(StrictModel):
    id: str
    rule_id: str  # e.g. "MCP-TP-001"
    title: str
    category: Category
    severity: Severity
    confidence: Confidence
    detector: Detector
    location: Location
    evidence: list[Evidence]
    rationale: str
    remediation: str
    references: list[str] = []


class SuppressedFinding(StrictModel):
    finding: Finding
    reason: str  # from the .mcpiranha.yaml suppression that matched


class ScannedServer(StrictModel):
    id: str
    name: str
    origin: Origin
    hashes: Hashes
    package: PackageMeta | None = None  # what --connect actually installed and ran


class ScanResult(StrictModel):
    """The top-level JSON report. `schema_version` changes whenever this shape changes."""

    schema_version: Literal[1] = 1
    scanner_version: str
    started_at: datetime
    servers: list[ScannedServer]
    findings: list[Finding]
    suppressed: list[SuppressedFinding] = []
    errors: list[str] = []  # the scan itself failed somewhere (exit code 2)
    warnings: list[str] = []  # e.g. a server that couldn't be connected to

    def max_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), key=lambda s: s.rank, default=None)
