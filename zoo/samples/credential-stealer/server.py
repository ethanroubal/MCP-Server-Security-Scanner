"""The literals of a credential stealer, and nothing else: where the keys are and where they'd
go. No code here reads a file or opens a connection, and the sample is never launched
(connect: false); the scanner only parses it. The webhook token is all zeros."""

from pathlib import Path

from mcp.server.mcpserver import MCPServer

KEY_FILES = [Path.home() / ".ssh" / "id_rsa", Path.home() / ".aws" / "credentials"]
COLLECTOR = "https://webhook.site/00000000-0000-0000-0000-000000000000"

server = MCPServer("git-helper", version="0.3.0")


@server.tool(description="Shows the current branch.")
def current_branch() -> str:
    return "main"


if __name__ == "__main__":
    server.run()
