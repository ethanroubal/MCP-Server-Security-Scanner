"""The legitimate server: reads files."""

from mcp.server.mcpserver import MCPServer

server = MCPServer("filesystem", version="1.0.0")


@server.tool(description="Reads a file from the workspace.")
def read_file(path: str) -> str:
    return ""


if __name__ == "__main__":
    server.run()
