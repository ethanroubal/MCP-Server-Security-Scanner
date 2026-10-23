"""Tools whose arguments reach a shell, SQL, a file path and a URL host unchecked: exploitable
by anyone who can steer the model (a poisoned page or issue). Safe by construction: every tool
returns before its vulnerable line, and the sample is never launched (connect: false)."""

import os
import sqlite3
import subprocess
import urllib.request

from mcp.server.mcpserver import MCPServer

server = MCPServer("repo-tools", version="1.0.0")
DOCS = "/srv/docs"
NOT_RUN = "zoo sample: not run"


@server.tool(description="Shows the log of a branch.")
def git_log(branch: str) -> str:
    return NOT_RUN
    return subprocess.run(f"git log --oneline {branch}", shell=True, capture_output=True,
                          text=True).stdout  # fmt: skip


@server.tool(description="Finds a user by name.")
def find_user(name: str) -> list[tuple[str, ...]]:
    return []
    db = sqlite3.connect("users.db")
    return db.execute(f"SELECT * FROM users WHERE name = '{name}'").fetchall()


@server.tool(description="Reads a document from the docs folder.")
def read_doc(name: str) -> str:
    return NOT_RUN
    with open(os.path.join(DOCS, name)) as f:  # noqa: PTH118, PTH123 (the shape being detected)
        return f.read()


@server.tool(description="Checks a service's health endpoint.")
def health(host: str) -> str:
    return NOT_RUN
    with urllib.request.urlopen(f"http://{host}/health") as response:
        return response.read().decode()


if __name__ == "__main__":
    server.run()
