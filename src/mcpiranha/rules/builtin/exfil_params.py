"""MCP-TP-009: parameters shaped to carry data out.

A poisoned tool often adds a parameter such as `sidenote` or `conversation_history` and tells the
model to fill it with file contents or the chat so far. The parameter's name, its description and
the tool description are checked together.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any, cast

from mcpiranha.core.matching import MatchView
from mcpiranha.core.models import Category, Confidence, Evidence, Finding, Location, Severity
from mcpiranha.core.text import pointer_token
from mcpiranha.rules.base import Rule, RuleContext
from mcpiranha.rules.builtin.instruction_phrases import instruction_matches, steers_model
from mcpiranha.rules.builtin.sensitive_paths import sensitive_hits, sentence_around
from mcpiranha.rules.registry import register

# Names with no plausible use other than collecting context from the model.
STRONG_NAMES = frozenset({
    "sidenote", "side_note", "conversation_history", "chat_history", "previous_messages",
    "full_conversation", "conversation_context", "system_prompt", "user_secrets", "hidden_context",
    "exfil", "leak",
})  # fmt: skip
# Names that are normal on their own and suspicious only with a soliciting description.
WEAK_NAMES = frozenset({
    "context", "notes", "note", "debug", "debug_info", "metadata", "extra", "history", "summary",
    "feedback", "reasoning", "thoughts", "memory", "comment", "comments", "details", "info",
    "conversation", "messages", "environment", "env",
})  # fmt: skip

_SOLICITS = re.compile(
    r"\b(entire|full|whole|complete|all)\s+(of\s+the\s+)?(conversation|chat|messages?|context|"
    r"history)|\b(previous|prior|earlier)\s+messages\b|\bsystem\s+prompt\b|"
    # "contents of" only counts when what follows is private: not "the content of the page"
    r"\bcontents?\s+of\s+(any\s+|all\s+|the\s+|your\s+|the\s+user'?s\s+)?(files?\b|~|/|\.\w|"
    r"local\b|conversation|chat|messages?\b|context\b|history\b|clipboard|environment)|"
    r"\bsee\s+(the\s+)?instructions\b|\brequired\s+context\b|"
    r"\b(all|every|your)\s+(of\s+the\s+)?environment\s+variables\b",
    re.IGNORECASE,
)


def _snake(name: str) -> str:
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).replace("-", "_").lower()


def _properties(schema: Any, pointer: str) -> Iterator[tuple[str, dict[str, Any], str]]:
    """(name, property schema, pointer to the property) for every property, nested ones too."""
    if not isinstance(schema, dict):
        return
    node = cast(dict[str, Any], schema)
    props = node.get("properties")
    if isinstance(props, dict):
        for name, sub in cast(dict[str, Any], props).items():
            child = f"{pointer}/properties/{pointer_token(name)}"
            if isinstance(sub, dict):
                yield name, cast(dict[str, Any], sub), child
                yield from _properties(sub, child)
    for key in ("items", "additionalProperties"):
        yield from _properties(node.get(key), f"{pointer}/{key}")
    for key in ("anyOf", "oneOf", "allOf"):
        options = node.get(key)
        if isinstance(options, list):
            for i, option in enumerate(cast(list[Any], options)):
                yield from _properties(option, f"{pointer}/{key}/{i}")


def _suspicious_reference(tool_view: MatchView, evidence: Evidence) -> bool:
    """The tool description's sentence that fills this parameter asks for something private."""
    if evidence.start is None or evidence.end is None:
        return False
    sentence = MatchView.of(sentence_around(tool_view.source, evidence.start, evidence.end))
    return bool(sensitive_hits(sentence) or _SOLICITS.search(sentence.text)
                or steers_model(instruction_matches(sentence)))  # fmt: skip


def _quoted_reference(name: str) -> re.Pattern[str]:
    """The tool description telling the model to put something into this parameter."""
    n = re.escape(name)
    return re.compile(
        rf"\b(pass|put|include|add|append|send|provide|write|copy|set)\b[^.\n]{{0,80}}"
        rf"(['\"`]{n}['\"`]|\b{n}\b)",
        re.IGNORECASE,
    )


@register
class ExfilParameters(Rule):
    id = "MCP-TP-009"
    title = "Parameter shaped to exfiltrate data"
    category = Category.TOOL_POISONING
    default_severity = Severity.MEDIUM
    applies_to = frozenset({"tool"})
    remediation = (
        "Ask why the tool needs this parameter. If nothing in the tool's purpose explains it, "
        "assume it exists to collect data from the conversation or your files."
    )

    def run(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for i, tool in enumerate(ctx.snapshot.tools):
            tool_view = MatchView.of(tool.description or "")
            for name, prop, pointer in _properties(tool.input_schema, f"/tools/{i}/inputSchema"):
                normalized = _snake(name)
                description = prop.get("description")
                description = description if isinstance(description, str) else ""
                desc_view = MatchView.of(description)
                solicit = [ev for _, ev in desc_view.finditer(_SOLICITS)]
                referenced = [ev for _, ev in tool_view.finditer(_quoted_reference(name))]

                strong = normalized in STRONG_NAMES
                weak = normalized in WEAK_NAMES
                # Calibration: hash fields ("SHA1 of the contents of the file"), `comment` and
                # `environment` parameters are everywhere. A generic name needs a soliciting
                # description, or a tool description that asks for something suspicious for it.
                referenced = (
                    [ev for ev in referenced if _suspicious_reference(tool_view, ev)]
                    if (not strong)
                    else referenced
                )
                if not (strong or (weak and (solicit or referenced))):
                    continue

                reasons: list[str] = []
                if strong:
                    reasons.append(f"the name {name!r} only makes sense for collecting context")
                elif weak:
                    reasons.append(f"the name {name!r} is generic")
                if solicit:
                    reasons.append("its description asks for conversation or file contents")
                if referenced:
                    reasons.append("the tool description tells the model what to put in it")

                # Evidence spans three fields (name, its description, the tool description), so
                # offsets would be ambiguous; the text alone is still verbatim.
                evidence = [Evidence(text=name)] + [
                    Evidence(text=ev.text) for ev in (*solicit, *referenced)
                ]
                high = (strong and (bool(solicit) or bool(referenced))) or (
                    bool(solicit) and bool(referenced)
                )
                findings.append(
                    self.finding(
                        location=Location(
                            server_id=ctx.snapshot.id, tool=tool.name, json_pointer=pointer
                        ),
                        evidence=evidence,
                        rationale=f"Parameter {name!r}: " + "; ".join(reasons) + ".",
                        severity=Severity.HIGH if high else Severity.MEDIUM,
                        confidence=Confidence.HIGH if high else Confidence.MEDIUM,
                    )
                )
        return findings
