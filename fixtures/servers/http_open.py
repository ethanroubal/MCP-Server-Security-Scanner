"""An unauthenticated Streamable-HTTP server with a state-changing tool. Usage: http_open.py PORT"""

import sys

from mcp.server.mcpserver import MCPServer

server = MCPServer("open-records", version="1.0.0")


@server.tool(description="Deletes a record by id.")
def delete_record(record_id: str) -> str:
    return "ok"


@server.tool(description="Looks up a record by id.")
def get_record(record_id: str) -> str:
    return "{}"


if __name__ == "__main__":
    server.run("streamable-http", host="127.0.0.1", port=int(sys.argv[1]))
