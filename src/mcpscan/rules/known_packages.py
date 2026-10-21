"""Widely used MCP server packages: the names typosquatters imitate.

This is a seed list. Phase 3 replaces it with data from the MCP registry and package-registry
download counts. Being on this list says nothing about a package's safety; it only means a
near-miss of the name is suspicious.
"""

KNOWN_NPM: frozenset[str] = frozenset({
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-gitlab",
    "@modelcontextprotocol/server-slack",
    "@modelcontextprotocol/server-postgres",
    "@modelcontextprotocol/server-puppeteer",
    "@modelcontextprotocol/server-brave-search",
    "@modelcontextprotocol/server-google-maps",
    "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/server-sequential-thinking",
    "@modelcontextprotocol/server-everything",
    "@modelcontextprotocol/server-redis",
    "@modelcontextprotocol/inspector",
    "@playwright/mcp",
    "@upstash/context7-mcp",
    "@notionhq/notion-mcp-server",
    "@sentry/mcp-server",
    "@supabase/mcp-server-supabase",
    "@stripe/mcp",
    "@cloudflare/mcp-server-cloudflare",
    "@azure/mcp",
    "firecrawl-mcp",
    "figma-developer-mcp",
    "mcp-remote",
})  # fmt: skip

KNOWN_PYPI: frozenset[str] = frozenset({
    "mcp-server-git",
    "mcp-server-fetch",
    "mcp-server-time",
    "mcp-server-sqlite",
    "mcp",
    "fastmcp",
})  # fmt: skip
