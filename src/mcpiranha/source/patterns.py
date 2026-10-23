"""Checks on string literals, shared by the Python and JavaScript analyzers.

Only strings that look like a path or URL count: tool descriptions mention `~/.ssh` and
webhooks in prose, and the tool-poisoning rules already judge those.
"""

from __future__ import annotations

import re

from mcpiranha.core.models import SourceHitKind

EMAIL = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
# A recipient in a raw message header: "Bcc: someone@example.com"
HEADER_RECIPIENT = re.compile(r"(?im)^\s*b?cc\s*:\s*[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
RECIPIENT_KEYS = frozenset({"bcc", "cc"})
SECRET_WORDS = re.compile(r"token|secret|passw|api_?key|apikey|credential|private_?key|auth",
                          re.IGNORECASE)  # fmt: skip

_SENSITIVE_PATH = re.compile(
    r"(^|[/\\~])(\.ssh([/\\]|$)|id_(rsa|ed25519|ecdsa|dsa)\b|\.aws[/\\]credentials|\.npmrc$"
    r"|\.pypirc$|\.netrc$|\.git-credentials$|\.docker[/\\]config\.json|\.kube[/\\]config"
    r"|\.gnupg([/\\]|$)|Library[/\\]Keychains|\.config[/\\]gcloud|wallet\.dat$"
    r"|Login Data$|Local State$)"
)
# Path segments that name a credential store on their own: path.join(home, ".ssh", "id_rsa")
_SENSITIVE_SEGMENTS = frozenset({".ssh", ".aws", ".gnupg", "id_rsa", "id_ed25519", ".npmrc",
                                 ".netrc", ".pypirc", ".git-credentials", ".kube"})  # fmt: skip

# Request catchers, tunnels and paste sites used to receive stolen data. Hardcoded in a server,
# they're never a feature (a server that posts to a user's webhook takes the URL as input).
_EXFIL_HOST = re.compile(
    r"https?://(?:[\w-]+\.)*(webhook\.site|pipedream\.net|requestbin\.(?:com|net)|"
    r"(?:[\w-]+\.)?ngrok(?:-free)?\.(?:io|app|dev)|interact\.sh|oast\.(?:fun|pro|live|site|online|me)|"
    r"burpcollaborator\.net|requestcatcher\.com|beeceptor\.com|hookbin\.com|webhook\.cool|"
    r"canarytokens\.(?:com|org)|transfer\.sh)(?=[/:?#]|$)"
    r"|https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+",
    re.IGNORECASE,
)


_REVERSE_SHELL = re.compile(
    r"/dev/tcp/[\w.\-$]+/\d+|\bbash\s+-i\s*>&|\bnc(at)?\b[^|;\n]{0,40}\s-e\s*/bin/(ba)?sh"
    r"|\bmkfifo\b[^;\n]{0,40};\s*(cat|nc)\b|\bsocat\b[^\n]{0,60}\bexec:"
    r"|Net\.Sockets\.TCPClient|import\s+socket\s*,\s*subprocess",
    re.IGNORECASE,
)
_MINER = re.compile(
    r"stratum\+(tcp|ssl|tls)://|\bxmrig\b|\bcryptonight\b|--donate-level|\bcoinhive\b"
    r"|(supportxmr|minexmr|nanopool|moneroocean|hashvault|c3pool|2miners)\.(com|org|pro|stream)",
    re.IGNORECASE,
)
_WIPE = re.compile(
    r"\brm\s+-[a-z]*r[a-z]*f?[a-z]*\s+(--no-preserve-root\s+)?(~/?|\$HOME/?|/)(\*)?(\s|$|['\"])"
    r"|\bdel\s+/[sq]\s+/[sq]\s+[a-z]:\\|\bformat\s+[a-z]:|\bmkfs\.\w+\s+/dev/"
    r"|\bdd\s+if=/dev/(zero|urandom)\s+of=/dev/[sh]d|\bvssadmin\s+delete\s+shadows",
    re.IGNORECASE,
)
_CRON_INSTALL = re.compile(r"\bcrontab\s+-(?!l\b)|\(\s*crontab\s+-l|schtasks(\.exe)?\s+/create",
                           re.IGNORECASE)  # fmt: skip
# Paths that run code later when written to. Only counted when the code writes them.
_PERSIST_PATH = re.compile(
    r"(^|[/\\~])(\.bashrc|\.bash_profile|\.bash_login|\.zshrc|\.zprofile|\.zshenv|\.profile"
    r"|\.config/fish/config\.fish|Library/LaunchAgents|Library/LaunchDaemons|\.config/autostart"
    r"|\.config/systemd/user|/etc/systemd/system|/etc/cron|/etc/rc\.local|\.git/hooks"
    r"|/etc/profile|/etc/ld\.so\.preload)($|[/\\])"
    r"|CurrentVersion\\Run",
    re.IGNORECASE,
)
# MCP client configs: a server that writes one can add servers or switch on auto-approve.
_CLIENT_CONFIG = re.compile(
    r"claude_desktop_config\.json|\.claude\.json$|\.claude/settings(\.local)?\.json"
    r"|\.cursor/mcp\.json|\.vscode/mcp\.json|windsurf/mcp_config\.json"
    r"|cline_mcp_settings\.json|mcp_settings\.json|\.gemini/settings\.json"
    r"|\.codex/config\.toml|\.kiro/settings/mcp\.json|\.amazonq/(default\.json|mcp\.json)"
    r"|\.continue/config\.(json|yaml)|opencode\.jsonc?$|\.lmstudio/mcp\.json",
    re.IGNORECASE,
)
AUTO_APPROVE_KEYS = frozenset({"autoApprove", "alwaysAllow", "trust", "auto_approve"})
WRITE_CALLS = frozenset({"open", "write_text", "write_bytes", "copyfile", "copy", "copy2", "move",
                         "symlink", "symlink_to", "touch", "writeFile", "writeFileSync",
                         "appendFile", "appendFileSync", "createWriteStream", "copyFile",
                         "copyFileSync", "rename", "renameSync", "symlinkSync", "outputFile",
                         "outputFileSync", "writeJson", "writeJsonSync"})  # fmt: skip
# Python open() modes that write
WRITE_MODES = re.compile(r"[wax+]")


# Command strings only count when the code runs them: deny-lists, docs and fuzzers are full of
# `rm -rf /` and `bash -i >& /dev/tcp/...` (calibration: 5 of 84 packages, all benign).
EXEC_CALLS = frozenset({"exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync",
                        "execa", "execaSync", "execaCommand", "system", "popen", "Popen", "run",
                        "call", "check_call", "check_output", "getoutput", "getstatusoutput",
                        "create_subprocess_shell", "create_subprocess_exec"})  # fmt: skip
NEEDS_EXEC: frozenset[str] = frozenset({"reverse_shell", "destructive", "persistence"})
APPROVE_SETTING = re.compile(r"""['"]?(autoApprove|alwaysAllow|auto_approve)['"]?\s*[:=]"""
                             r"""|['"]trust['"]\s*:\s*true""")  # fmt: skip


def string_hits(text: str) -> list[tuple[SourceHitKind, str]]:
    """(kind, detail) for a string literal. Kinds in NEEDS_EXEC only count when the string is
    executed; the analyzers check that."""
    hits: list[tuple[SourceHitKind, str]] = []
    if path := sensitive_path(text):
        hits.append(("sensitive_file", f"names {path}"))
    if url := exfil_host(text):
        hits.append(("exfil_host", f"hardcoded {url}"))
    if HEADER_RECIPIENT.search(text):
        hits.append(("hardcoded_recipient", "a Bcc/Cc header with a fixed address"))
    if len(text) < 2000:  # commands, not documents
        if m := _REVERSE_SHELL.search(text):
            hits.append(("reverse_shell", f"reverse-shell command: {m.group(0)}"))
        if m := _MINER.search(text):
            hits.append(("miner", f"crypto-mining reference: {m.group(0)}"))
        if m := _WIPE.search(text):
            hits.append(("destructive", f"wipes files: {m.group(0).strip()}"))
        if m := _CRON_INSTALL.search(text):
            hits.append(("persistence", f"installs a scheduled task: {m.group(0)}"))
    return hits


def written_path_kind(text: str) -> tuple[SourceHitKind, str] | None:
    """(kind, detail) for a path that only matters when the code writes it."""
    text = text.strip()
    if not text or not _token_like(text):
        return None
    if m := _PERSIST_PATH.search(text):
        return "persistence", f"writes {m.group(0).strip('/')} (runs code later)"
    if m := _CLIENT_CONFIG.search(text):
        return "client_config", f"writes the MCP client config {m.group(0)}"
    return None


def _token_like(text: str) -> bool:
    """A path, URL or identifier rather than a sentence."""
    return len(text) < 300 and text.count(" ") <= 1


def sensitive_path(text: str) -> str | None:
    text = text.strip()
    if not text or not _token_like(text):
        return None
    if text in _SENSITIVE_SEGMENTS or _SENSITIVE_PATH.search(text):
        return text
    return None


def exfil_host(text: str) -> str | None:
    m = _EXFIL_HOST.search(text)
    if not m:
        return None
    # the URL itself must not be prose: take the whitespace-delimited token around it
    start = text.rfind(" ", 0, m.start()) + 1
    end = text.find(" ", m.end())
    token = text[start : end if end >= 0 else len(text)]
    return token if len(token) < 300 else None


def recipient(key: str, value: str) -> bool:
    return key.lower() in RECIPIENT_KEYS and bool(EMAIL.match(value.strip()))
