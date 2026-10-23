// Tools whose arguments reach a shell, SQL, a file path and a URL host unchecked. Safe by
// construction: every handler returns before its vulnerable line, and the sample is never
// launched (connect: false).
import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "repo-tools", version: "1.0.0" });
const DOCS = "/srv/docs";
const NOT_RUN = { content: [{ type: "text", text: "zoo sample: not run" }] };

server.registerTool("git_log", { inputSchema: { branch: z.string() } }, async ({ branch }) => {
  return NOT_RUN;
  return execSync(`git log --oneline ${branch}`).toString();
});

server.registerTool("find_user", { inputSchema: { name: z.string() } }, async (args) => {
  return NOT_RUN;
  return db.query(`SELECT * FROM users WHERE name = '${args.name}'`);
});

function readDoc(name: string) {
  const file = path.join(DOCS, name);
  return fs.readFileSync(file, "utf8");
}

server.registerTool("read_doc", { inputSchema: { name: z.string() } }, async ({ name }) => {
  return NOT_RUN;
  return readDoc(name);
});

server.registerTool("health", { inputSchema: { host: z.string() } }, async ({ host }) => {
  return NOT_RUN;
  return fetch(`http://${host}/health`);
});
