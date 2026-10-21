"""A Streamable-HTTP server that requires OAuth, with a built-in authorization server that
approves every sign-in immediately. It also accepts the bearer token `static-test-token`.
Usage: http_oauth.py PORT"""

import secrets
import sys
import time

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.mcpserver import MCPServer
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

STATIC_TOKEN = "static-test-token"


class AutoApprove:
    def __init__(self) -> None:
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.codes: dict[str, AuthorizationCode] = {}
        self.tokens = {STATIC_TOKEN: AccessToken(token=STATIC_TOKEN, client_id="static", scopes=[])}

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self.clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        assert client_info.client_id is not None
        self.clients[client_info.client_id] = client_info

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        code = secrets.token_urlsafe(16)
        assert client.client_id is not None
        self.codes[code] = AuthorizationCode(
            code=code,
            scopes=params.scopes or [],
            expires_at=time.time() + 300,
            client_id=client.client_id,
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=params.resource,
        )
        return construct_redirect_uri(str(params.redirect_uri), code=code, state=params.state)

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, code: str
    ) -> AuthorizationCode | None:
        return self.codes.get(code)

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        self.codes.pop(authorization_code.code, None)
        token = secrets.token_urlsafe(16)
        assert client.client_id is not None
        self.tokens[token] = AccessToken(
            token=token,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            resource=authorization_code.resource,
        )
        return OAuthToken(access_token=token, token_type="Bearer", expires_in=3600)

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        return None

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list[str]
    ) -> OAuthToken:
        raise NotImplementedError

    async def load_access_token(self, token: str) -> AccessToken | None:
        return self.tokens.get(token)

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        self.tokens.pop(token.token, None)


port = int(sys.argv[1])
base = f"http://127.0.0.1:{port}"
server = MCPServer(
    "oauth-records",
    version="1.0.0",
    auth_server_provider=AutoApprove(),
    auth=AuthSettings(
        issuer_url=base,
        resource_server_url=f"{base}/mcp",
        client_registration_options=ClientRegistrationOptions(enabled=True),
        validate_token_resource=False,
    ),
)


@server.tool(description="Reads a record by id.")
def get_record(record_id: str) -> str:
    return "{}"


if __name__ == "__main__":
    server.run("streamable-http", host="127.0.0.1", port=port)
