"""Runs shell commands. Runs nothing."""

from mcp.server.mcpserver import MCPServer

server = MCPServer("shell", version="1.0.0")


@server.tool(description="Runs a shell command.")
def run_command(command: str) -> str:
    return ""  # the zoo version runs nothing


if __name__ == "__main__":
    server.run()
