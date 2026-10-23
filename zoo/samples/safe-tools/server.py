"""The same tools as vulnerable-tools-py, written safely, plus tools that pass input through
whole by design (a shell tool, a SQL tool, a fetch tool). None of them may trigger the
injection rules. Never launched (connect: false); the shell and SQL tools return first."""

import shlex
import sqlite3
import subprocess
import urllib.request
from pathlib import Path

from mcp.server.mcpserver import MCPServer

server = MCPServer("repo-tools-safe", version="1.0.0")
DOCS = Path("/srv/docs")
NOT_RUN = "zoo sample: not run"


@server.tool(description="Shows the log of a branch.")
def git_log(branch: str) -> str:
    return NOT_RUN
    return subprocess.run(["git", "log", "--oneline", branch], capture_output=True,
                          text=True).stdout  # fmt: skip


@server.tool(description="Shows the log of a branch (quoted).")
def git_log_quoted(branch: str) -> str:
    return NOT_RUN
    command = f"git log --oneline {shlex.quote(branch)}"
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout


@server.tool(description="Finds a user by name.")
def find_user(name: str) -> list[tuple[str, ...]]:
    return []
    db = sqlite3.connect("users.db")
    return db.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchall()


@server.tool(description="Reads a document from the docs folder.")
def read_doc(name: str) -> str:
    target = (DOCS / name).resolve()
    if not target.is_relative_to(DOCS):
        raise ValueError("outside the docs folder")
    return target.read_text()


@server.tool(description="Gets a page from the docs site.")
def docs_page(slug: str) -> str:
    return NOT_RUN
    with urllib.request.urlopen(f"https://docs.example.invalid/{slug}") as response:
        return response.read().decode()


@server.tool(description="Runs a shell command (by design).")
def run_command(command: str) -> str:
    return NOT_RUN
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout


@server.tool(description="Runs a SQL query (by design).")
def run_sql(sql: str) -> list[tuple[str, ...]]:
    return []
    return sqlite3.connect("users.db").execute(sql).fetchall()


@server.tool(description="Fetches a URL (by design).")
def fetch(url: str) -> str:
    return NOT_RUN
    with urllib.request.urlopen(url) as response:
        return response.read().decode()


if __name__ == "__main__":
    server.run()
