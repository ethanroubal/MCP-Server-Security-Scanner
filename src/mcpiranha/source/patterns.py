"""Checks on string literals, shared by the Python and JavaScript analyzers.

Only strings that look like a path or URL count: tool descriptions mention `~/.ssh` and
webhooks in prose, and the tool-poisoning rules already judge those.
"""

from __future__ import annotations

import re

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
