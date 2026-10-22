"""Capability labels: what each tool can do, as far as an attacker is concerned.

Toxic-flow analysis (MCP-TF) needs to know which tools take in content an attacker can write
(web pages, issues, email), which read private data, which can send data out, and which run code
or destroy things. Labels come from:

- tool names, split into words (`get_issue`, `browserNavigate`, `slack.post-message`),
- parameter names (a `url` parameter makes a fetch an outbound channel: data goes in the URL),
- a table of well-known servers, so servers read from config files (no `--connect`) still count.

Descriptions aren't used: calibration showed they mention every capability in passing.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, cast

from mcpiranha.core.launch import package_ref
from mcpiranha.core.models import CapabilityLabel, ServerSnapshot, ToolDef
from mcpiranha.flows.known import KNOWN_SERVERS

L = CapabilityLabel

_READ = {"read", "get", "list", "search", "query", "fetch", "show", "view", "find", "describe",
         "download", "retrieve", "lookup", "browse", "scrape", "crawl", "navigate", "open",
         "export", "cat", "load", "check"}  # fmt: skip
# Verbs that fetch outside content by themselves. "fetch" and "get" alone don't: they're
# generic (fetchAccessibilityIssues), so they need a URL parameter or a web noun.
_FETCH = {"scrape", "crawl", "browse", "navigate", "goto", "visit", "websearch", "curl", "wget",
          "webfetch"}  # fmt: skip
# Not "page" (OneNote, Slides, Notion pages are private) or "url" (get_download_url returns one).
_WEB_NOUNS = {"web", "site", "website", "html", "http", "internet", "online", "google"}
_UNTRUSTED_NOUNS = {"web", "site", "website", "browser", "html", "issue",
                    "issues", "pr", "prs", "pull", "comment", "comments", "email", "emails", "mail",
                    "inbox", "message", "messages", "ticket", "tickets", "tweet", "tweets", "feed",
                    "rss", "news", "chat", "channel", "thread", "threads", "discussion", "review",
                    "reviews", "post", "posts", "reddit", "slack", "discord", "notification",
                    "notifications"}  # fmt: skip
_PRIVATE_NOUNS = {"file", "files", "directory", "dir", "folder", "document", "documents", "drive",
                  "note", "notes", "database", "db", "table", "tables", "sql", "record", "records",
                  "customer", "customers", "contact", "contacts", "calendar", "event", "events",
                  "email", "emails", "mail", "inbox", "message", "messages", "repo", "repository",
                  "secret", "secrets", "credential", "credentials", "env", "password", "passwords",
                  "account", "accounts", "memory", "memories", "clipboard", "screenshot", "code",
                  "source", "log", "logs", "history", "channel", "thread", "user", "users",
                  "profile", "invoice", "invoices", "payment", "payments", "order",
                  "orders"}  # fmt: skip
_SEND = {"send", "post", "publish", "reply", "notify", "tweet", "upload", "share", "invite",
         "forward", "email", "webhook", "dm", "broadcast", "sms", "push"}  # fmt: skip
# Words that are sends as verbs but often nouns: a read verb wins (discourse_read_post), and
# "forward" needs something to forward (scraping_browser_go_forward navigates).
_SEND_NOUNS = {"post", "tweet", "email", "push", "webhook", "dm", "sms"}
_FORWARDABLE = {"mail", "email", "message", "messages", "event", "draft"}
# Objects that stay in the user's own account until something sends them.
_NOT_SENT = {"draft", "drafts", "folder", "folders"}
_CREATE = {"create", "add", "update", "submit", "open", "comment", "write", "set", "edit"}
_OUTBOUND_NOUNS = {"message", "messages", "email", "mail", "comment", "comments", "issue",
                   "issues", "pr", "pull", "post", "tweet", "webhook", "chat", "sms",
                   "notification", "invite", "review", "discussion", "gist",
                   "slack", "discord"}  # fmt: skip
# When a tool's name ends in one of these, it returns facts about the data, not the data or
# anyone's writing (get_file_info, list-mail-folders, list_tables, get-mail-tips).
_METADATA = {"info", "structure", "schema", "permission", "permissions", "access", "link",
             "tips", "settings", "folders", "rules", "overrides", "tables",
             "databases", "collections", "indexes"}  # fmt: skip
# Unambiguous on their own; the nouns below need a run verb (create-onenote-notebook and
# addPercySnapshotCommands don't run anything).
_EXEC = {"exec", "execute", "shell", "bash", "terminal", "eval", "repl", "interpreter",
         "subprocess"}  # fmt: skip
# "evaluate" needs code to evaluate (evaluate_reconstruction_coverage doesn't run any).
_EVALUATES = {"browser", "debugger", "expression", "js", "javascript", "script"}
_EXEC_NOUNS = {"command", "commands", "script", "scripts", "code", "program", "binary",
               "process", "python", "javascript", "js", "notebook", "cell",
               "container"}  # fmt: skip
_RUN = {"run", "start", "spawn", "launch", "invoke"}
_WRITE = {"write", "edit", "save", "patch", "apply", "move", "rename", "copy", "append", "mkdir"}
_FILE_NOUNS = {"file", "files", "directory", "dir", "folder", "path"}
# Not "kill" or "terminate": stopping a process loses no data.
_DESTROY = {"delete", "remove", "destroy", "truncate", "purge", "wipe", "reset", "rm", "rmdir",
            "uninstall", "revoke"}  # fmt: skip
# "drop" needs a data store (browser_drop is drag and drop).
_DROPPABLE = {"collection", "database", "db", "table", "index", "schema", "keyspace", "bucket"}
_QUERY = {"query", "sql"}
_URL_PARAMS = {"url", "uri", "href", "link", "endpoint", "webhook", "webhook_url", "target_url"}


def words(name: str) -> list[str]:
    """`browserNavigate`, `get_issue`, `slack.post-message` -> lowercase words."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", name)
    return [w for w in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if w]


def _param_names(schema: Mapping[str, Any]) -> set[str]:
    props = schema.get("properties")
    return (
        {str(k).lower() for k in cast(dict[str, Any], props)} if isinstance(props, dict) else set()
    )


def label_tool(tool: ToolDef) -> dict[CapabilityLabel, str]:
    """Capability -> the reason it was assigned, for one tool."""
    names = words(tool.name)
    w = set(names)
    params = _param_names(tool.input_schema)
    labels: dict[CapabilityLabel, str] = {}

    def add(label: CapabilityLabel, reason: str) -> None:
        labels.setdefault(label, reason)

    # Annotations aren't used: calibration found openWorldHint and destructiveHint set loosely
    # (a "find organizations" tool marked open-world, browser_click marked destructive).
    # read_resource(uri) and get_sentry_resource(url) read from the server's own service
    url_param = bool(params & _URL_PARAMS) and not w & {"resource", "resources"}
    reads = bool(w & _READ) and names[-1] not in _METADATA
    generic_read = bool(w & {"fetch", "get", "search", "read", "open"})
    fetches = (
        bool(w & _FETCH) or w == {"fetch"} or (generic_read and (bool(w & _WEB_NOUNS) or url_param))
    )
    if fetches:
        add(L.INGESTS_UNTRUSTED_CONTENT, "fetches outside content")
        if url_param:
            add(L.EXTERNAL_COMMUNICATION, "requests a URL the model chooses (data can go in it)")
    if reads and w & _UNTRUSTED_NOUNS:
        add(L.INGESTS_UNTRUSTED_CONTENT, f"reads {', '.join(sorted(w & _UNTRUSTED_NOUNS))}")
    if reads and w & _PRIVATE_NOUNS:
        add(L.READS_PRIVATE_DATA, f"reads {', '.join(sorted(w & _PRIVATE_NOUNS))}")
    if w & _QUERY and w & (_RUN | {"execute", "exec"}):
        add(L.READS_PRIVATE_DATA, "queries a database")
    sends = w & _SEND
    if w & _READ:
        sends -= _SEND_NOUNS
    if not w & _FORWARDABLE:
        sends -= {"forward"}
    if ((sends or (w & _CREATE and w & _OUTBOUND_NOUNS))
            and not (w & _NOT_SENT and "send" not in w)):  # fmt: skip
        add(L.EXTERNAL_COMMUNICATION, "sends or posts content")
    if w & _EXEC or (w & _RUN and w & _EXEC_NOUNS) or ("evaluate" in w and w & _EVALUATES):
        add(L.EXECUTES_CODE, "runs commands or code")
    if w & _WRITE and (w & _FILE_NOUNS or "write" in w):
        add(L.WRITES_FILES, "writes files")
    if w & _DESTROY or ("drop" in w and w & _DROPPABLE):
        add(L.DESTRUCTIVE, "deletes or destroys")
    return labels


@dataclass(frozen=True, slots=True)
class ToolCapabilities:
    server_id: str
    server: str
    tool: str
    labels: Mapping[CapabilityLabel, str]
    known: bool  # from the known-server table rather than the tool's own metadata
    auto_approved: bool  # the client runs it without asking

    @property
    def qualified(self) -> str:
        return f"{self.server}.{self.tool}"


def _known_tools(snapshot: ServerSnapshot) -> dict[str, set[CapabilityLabel]] | None:
    ref = package_ref(snapshot.launch)
    if ref is not None and ref.name in KNOWN_SERVERS:
        return KNOWN_SERVERS[ref.name]
    return KNOWN_SERVERS.get(snapshot.name.lower()) if snapshot.origin.kind == "config" else None


def server_capabilities(snapshot: ServerSnapshot) -> list[ToolCapabilities]:
    """Labels for every enabled tool of an enabled server. Uses the listed tools when there are
    any, else the known-server table."""
    settings = snapshot.client_settings
    if settings and settings.disabled:
        return []
    disabled: set[str] = set(settings.disabled_tools) if settings else set()

    def approved(tool: str) -> bool:
        return bool(settings and (settings.auto_approve_all or tool in settings.auto_approve))

    out: list[ToolCapabilities] = []
    if snapshot.tools_listed:
        for tool in snapshot.tools:
            labels = label_tool(tool)
            if labels and tool.name not in disabled:
                out.append(ToolCapabilities(snapshot.id, snapshot.name, tool.name, labels, False,
                                            approved(tool.name)))  # fmt: skip
        return out
    for name, labels in (_known_tools(snapshot) or {}).items():
        if name not in disabled:
            reasons = dict.fromkeys(labels, "known capability of this server")
            out.append(ToolCapabilities(snapshot.id, snapshot.name, name, reasons, True,
                                        approved(name)))  # fmt: skip
    return out


def inventory_capabilities(inventory: Iterable[ServerSnapshot]) -> list[ToolCapabilities]:
    return [cap for snapshot in inventory for cap in server_capabilities(snapshot)]
