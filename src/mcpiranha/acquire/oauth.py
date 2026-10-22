"""`--oauth`: sign in to a remote server the way an MCP client does, so its tools can be listed.

The SDK's OAuthClientProvider does the protocol work (metadata discovery, dynamic client
registration, PKCE, token exchange). This module supplies the two interactive pieces: opening the
authorization URL, and a one-shot HTTP listener on 127.0.0.1 for the redirect back.

Tokens are kept in memory for this run only and never written to disk or into any report.
"""

from __future__ import annotations

import threading
import webbrowser
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

import anyio
from mcp.client.auth.oauth2 import OAuthClientProvider
from mcp.shared.auth import (
    AuthorizationCodeResult,
    OAuthClientInformationFull,
    OAuthClientMetadata,
    OAuthToken,
)
from pydantic import AnyUrl

from mcpiranha import __version__

SIGN_IN_TIMEOUT = 300.0
OpenUrl = Callable[[str], None]


class OAuthError(Exception):
    pass


class MemoryTokenStorage:
    """TokenStorage that lives as long as one connection."""

    def __init__(self) -> None:
        self._tokens: OAuthToken | None = None
        self._client: OAuthClientInformationFull | None = None

    async def get_tokens(self) -> OAuthToken | None:
        return self._tokens

    async def set_tokens(self, tokens: OAuthToken) -> None:
        self._tokens = tokens

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        return self._client

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        self._client = client_info


class LoopbackCallback:
    """Receives the single authorization redirect on http://127.0.0.1:<random port>/callback."""

    def __init__(self) -> None:
        self.params: dict[str, str] | None = None
        received = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                parts = urlsplit(self.path)
                if parts.path != "/callback":
                    self.send_error(404)
                    return
                received.params = {k: v[0] for k, v in parse_qs(parts.query).items()}
                body = b"mcpiranha: sign-in finished. You can close this tab."
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: Any) -> None:
                return  # keep the authorization code out of the terminal

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        self.redirect_uri = f"http://127.0.0.1:{self._server.server_address[1]}/callback"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    async def wait(self, timeout: float = SIGN_IN_TIMEOUT) -> AuthorizationCodeResult:
        with anyio.move_on_after(timeout):
            while self.params is None:
                await anyio.sleep(0.1)
        params = self.params
        if params is None:
            raise OAuthError(f"no sign-in completed within {timeout:.0f}s")
        if "error" in params:
            detail = params.get("error_description") or params["error"]
            raise OAuthError(f"sign-in was refused: {detail}")
        if "code" not in params:
            raise OAuthError("the sign-in redirect carried no authorization code")
        return AuthorizationCodeResult(code=params["code"], state=params.get("state"),
                                       iss=params.get("iss"))  # fmt: skip

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def check_authorization_url(url: str) -> None:
    """The URL comes from the server's metadata: open only http(s). mcp-remote opened whatever it
    was given, and a crafted authorization_endpoint ran commands (CVE-2025-6514)."""
    parts = urlsplit(url)
    if (
        parts.scheme not in ("https", "http")
        or not parts.hostname
        or any(ord(c) < 0x21 or ord(c) == 0x7F for c in url)
    ):
        raise OAuthError(f"refusing to open the server's authorization URL: {url!r}")


def open_in_browser(url: str) -> None:
    import sys

    sys.stderr.write(f"Sign in to continue. If no browser opens, visit:\n  {url}\n")
    webbrowser.open(url)


def oauth_provider(server_url: str, callback: LoopbackCallback, open_url: OpenUrl
                   ) -> OAuthClientProvider:  # fmt: skip
    async def redirect(url: str) -> None:
        check_authorization_url(url)
        open_url(url)

    metadata = OAuthClientMetadata(
        client_name=f"mcpiranha {__version__}",
        redirect_uris=[AnyUrl(callback.redirect_uri)],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        token_endpoint_auth_method="none",  # public client: PKCE, no secret to store
    )
    return OAuthClientProvider(
        server_url=server_url,
        client_metadata=metadata,
        storage=MemoryTokenStorage(),
        redirect_handler=redirect,
        callback_handler=callback.wait,
    )
