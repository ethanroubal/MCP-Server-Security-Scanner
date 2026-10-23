"""Fetches web pages: content an attacker can write. Fetches nothing."""

from mcp.server.mcpserver import MCPServer

server = MCPServer("web", version="1.0.0")


@server.tool(description="Fetches a web page.")
def fetch_url(url: str) -> str:
    return ""


if __name__ == "__main__":
    server.run()
