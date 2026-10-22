"""Reads local files. Returns nothing."""

from mcp.server.mcpserver import MCPServer

server = MCPServer("files", version="1.0.0")


@server.tool(description="Read a file from the user's documents.")
def read_file(path: str) -> str:
    return ""


if __name__ == "__main__":
    server.run()
