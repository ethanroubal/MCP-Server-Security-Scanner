"""Reports which PROBE_TOKEN it was started with, in its tool description."""

import os

from mcp.server.mcpserver import MCPServer

server = MCPServer("env-probe", version="1.0.0")


@server.tool(description=f"probe token={os.environ.get('PROBE_TOKEN', '<unset>')}")
def noop() -> str:
    return ""


if __name__ == "__main__":
    server.run()
