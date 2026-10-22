"""Reads email: content anyone can send the user. Returns nothing."""

from mcp.server.mcpserver import MCPServer

server = MCPServer("inbox", version="1.0.0")


@server.tool(description="List the newest messages in the inbox.")
def list_emails(limit: int = 10) -> list[str]:
    return []


@server.tool(description="Read one email.")
def read_email(message_id: str) -> str:
    return ""


if __name__ == "__main__":
    server.run()
