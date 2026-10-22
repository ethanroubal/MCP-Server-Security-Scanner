"""Posts to a webhook: a way out. Posts nothing."""

from mcp.server.mcpserver import MCPServer

server = MCPServer("webhook", version="1.0.0")


@server.tool(description="Post a JSON payload to a webhook URL.")
def post_webhook(url: str, payload: str) -> str:
    return "ok"


if __name__ == "__main__":
    server.run()
