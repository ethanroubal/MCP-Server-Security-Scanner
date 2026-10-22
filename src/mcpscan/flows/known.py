"""Capabilities of widely used servers, keyed by package name (or a config entry's usual name).

Used when a server was only read from a config file, so toxic flows are found without
`--connect`. Listed tools always take precedence. Only the tools that matter for flows are
listed; tool names follow each server's own naming.
"""

from mcpscan.core.models import CapabilityLabel as L

_GITHUB = {
    "get_issue": {L.INGESTS_UNTRUSTED_CONTENT},
    "list_issues": {L.INGESTS_UNTRUSTED_CONTENT},
    "get_pull_request": {L.INGESTS_UNTRUSTED_CONTENT},
    "get_file_contents": {L.READS_PRIVATE_DATA},
    "search_code": {L.READS_PRIVATE_DATA},
    "create_issue": {L.EXTERNAL_COMMUNICATION},
    "add_issue_comment": {L.EXTERNAL_COMMUNICATION},
    "create_pull_request": {L.EXTERNAL_COMMUNICATION},
    "push_files": {L.EXTERNAL_COMMUNICATION},
}
_FETCH = {"fetch": {L.INGESTS_UNTRUSTED_CONTENT, L.EXTERNAL_COMMUNICATION}}
_BROWSER = {
    "browser_navigate": {L.INGESTS_UNTRUSTED_CONTENT, L.EXTERNAL_COMMUNICATION},
    "browser_snapshot": {L.INGESTS_UNTRUSTED_CONTENT},
    "browser_evaluate": {L.EXECUTES_CODE},
}

KNOWN_SERVERS: dict[str, dict[str, set[L]]] = {
    "@modelcontextprotocol/server-filesystem": {
        "read_text_file": {L.READS_PRIVATE_DATA},
        "read_file": {L.READS_PRIVATE_DATA},
        "write_file": {L.WRITES_FILES},
        "edit_file": {L.WRITES_FILES},
        "move_file": {L.WRITES_FILES},
    },
    "@modelcontextprotocol/server-github": _GITHUB,
    "github": _GITHUB,
    "@modelcontextprotocol/server-gitlab": {
        "get_file_contents": {L.READS_PRIVATE_DATA},
        "create_issue": {L.EXTERNAL_COMMUNICATION},
        "create_merge_request": {L.EXTERNAL_COMMUNICATION},
    },
    "@modelcontextprotocol/server-slack": {
        "slack_get_channel_history": {L.INGESTS_UNTRUSTED_CONTENT, L.READS_PRIVATE_DATA},
        "slack_get_thread_replies": {L.INGESTS_UNTRUSTED_CONTENT, L.READS_PRIVATE_DATA},
        "slack_post_message": {L.EXTERNAL_COMMUNICATION},
        "slack_reply_to_thread": {L.EXTERNAL_COMMUNICATION},
    },
    "@modelcontextprotocol/server-postgres": {"query": {L.READS_PRIVATE_DATA}},
    "@modelcontextprotocol/server-brave-search": {
        "brave_web_search": {L.INGESTS_UNTRUSTED_CONTENT, L.EXTERNAL_COMMUNICATION},
    },
    "@modelcontextprotocol/server-puppeteer": {
        "puppeteer_navigate": {L.INGESTS_UNTRUSTED_CONTENT, L.EXTERNAL_COMMUNICATION},
        "puppeteer_evaluate": {L.EXECUTES_CODE},
    },
    "@modelcontextprotocol/server-memory": {"read_graph": {L.READS_PRIVATE_DATA}},
    "mcp-server-fetch": _FETCH,
    "mcp/fetch": _FETCH,
    "fetch": _FETCH,
    "mcp-server-git": {"git_show": {L.READS_PRIVATE_DATA}, "git_diff": {L.READS_PRIVATE_DATA}},
    "mcp-server-sqlite": {
        "read_query": {L.READS_PRIVATE_DATA},
        "write_query": {L.DESTRUCTIVE},
    },
    "@playwright/mcp": _BROWSER,
    "playwright": _BROWSER,
    "chrome-devtools-mcp": {
        "navigate_page": {L.INGESTS_UNTRUSTED_CONTENT, L.EXTERNAL_COMMUNICATION},
        "evaluate_script": {L.EXECUTES_CODE},
    },
    "@wonderwhy-er/desktop-commander": {
        "read_file": {L.READS_PRIVATE_DATA},
        "start_process": {L.EXECUTES_CODE},
        "write_file": {L.WRITES_FILES},
    },
    "firecrawl-mcp": {"firecrawl_scrape": {L.INGESTS_UNTRUSTED_CONTENT, L.EXTERNAL_COMMUNICATION}},
    "@upstash/context7-mcp": {"get-library-docs": {L.INGESTS_UNTRUSTED_CONTENT}},
    "@notionhq/notion-mcp-server": {
        "API-post-search": {L.READS_PRIVATE_DATA, L.INGESTS_UNTRUSTED_CONTENT},
        "API-post-page": {L.EXTERNAL_COMMUNICATION},
    },
}
