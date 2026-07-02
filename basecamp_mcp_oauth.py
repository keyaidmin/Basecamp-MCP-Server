"""FastMCP OAuth provider that delegates user consent to Basecamp."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from typing import Any

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from basecamp_oauth import BasecampOAuth
import oauth_store


MCP_SCOPE = "basecamp"
AUTH_CODE_TTL_SECONDS = 5 * 60
MCP_ACCESS_TOKEN_TTL_SECONDS = 60 * 60
MCP_REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60
PENDING_STATE_TTL_SECONDS = 10 * 60
SERVICE_TOKEN_CLIENT_ID = "basecamp-mcp-service"


class BasecampAuthorizationCode(AuthorizationCode):
    """MCP authorization code bound to one Basecamp user."""

    user_id: str


class BasecampRefreshToken(RefreshToken):
    """MCP refresh token bound to one Basecamp user."""

    user_id: str


class BasecampAccessToken(AccessToken):
    """MCP access token bound to one Basecamp user."""

    user_id: str


def public_base_url() -> str:
    """Return the externally reachable server base URL."""
    value = os.getenv("PUBLIC_BASE_URL", "").strip().rstrip("/")
    if value:
        return value
    if os.getenv("ENVIRONMENT", "").lower() == "production":
        raise ValueError("PUBLIC_BASE_URL is required in production")
    return f"http://localhost:{os.getenv('MCP_PORT', '8051')}"


def basecamp_redirect_uri() -> str:
    """Return the Basecamp integration redirect URI."""
    return os.getenv("BASECAMP_REDIRECT_URI") or f"{public_base_url()}/basecamp/oauth/callback"


def _expires_at(expires_in: int | None) -> int | None:
    return oauth_store.now() + int(expires_in) if expires_in else None


def _account_id(account: dict[str, Any]) -> str:
    return str(account.get("id") or account.get("account_id") or "")


def _bc3_accounts(identity: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        account
        for account in identity.get("accounts", [])
        if account.get("product") in (None, "bc3") and _account_id(account)
    ]


def choose_active_account(identity: dict[str, Any]) -> str | None:
    """Choose the active Basecamp account from identity and environment policy."""
    accounts = _bc3_accounts(identity)
    configured_account_id = os.getenv("BASECAMP_ACCOUNT_ID")
    if configured_account_id:
        return configured_account_id if configured_account_id in {_account_id(account) for account in accounts} else None
    return _account_id(accounts[0]) if accounts else None


def extract_user_id(identity: dict[str, Any], access_token: str) -> str:
    """Extract a stable Basecamp user ID from a Launchpad identity response."""
    candidates = [
        identity.get("identity", {}).get("id") if isinstance(identity.get("identity"), dict) else None,
        identity.get("person", {}).get("id") if isinstance(identity.get("person"), dict) else None,
        identity.get("me", {}).get("id") if isinstance(identity.get("me"), dict) else None,
        identity.get("id"),
    ]
    for candidate in candidates:
        if candidate:
            return str(candidate)
    digest = hashlib.sha256(access_token.encode()).hexdigest()
    return f"token:{digest[:32]}"


def _serialize_auth_params(params: AuthorizationParams) -> dict[str, Any]:
    return {
        "state": params.state,
        "scopes": params.scopes or [MCP_SCOPE],
        "code_challenge": params.code_challenge,
        "redirect_uri": str(params.redirect_uri),
        "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
        "resource": params.resource,
    }


def _oauth_token_for(user_id: str, client_id: str, scopes: list[str], resource: str | None) -> OAuthToken:
    access_token = secrets.token_urlsafe(48)
    refresh_token = secrets.token_urlsafe(48)
    access_expires_at = oauth_store.now() + MCP_ACCESS_TOKEN_TTL_SECONDS
    refresh_expires_at = oauth_store.now() + MCP_REFRESH_TOKEN_TTL_SECONDS
    data = {
        "client_id": client_id,
        "user_id": user_id,
        "scopes": scopes,
        "resource": resource,
    }
    oauth_store.save_access_token(access_token, {**data, "expires_at": access_expires_at})
    oauth_store.save_refresh_token(refresh_token, {**data, "expires_at": refresh_expires_at})
    return OAuthToken(
        access_token=access_token,
        expires_in=MCP_ACCESS_TOKEN_TTL_SECONDS,
        scope=" ".join(scopes),
        refresh_token=refresh_token,
    )


def _configured_service_token(token: str) -> BasecampAccessToken | None:
    configured_token = os.getenv("BASECAMP_MCP_AUTH_TOKEN", "").strip()
    user_id = os.getenv("BASECAMP_MCP_AUTH_USER_ID", "").strip()
    if not configured_token or not user_id:
        return None
    if not hmac.compare_digest(token, configured_token):
        return None
    return BasecampAccessToken(
        token=token,
        client_id=SERVICE_TOKEN_CLIENT_ID,
        user_id=user_id,
        scopes=[MCP_SCOPE],
        expires_at=None,
        resource=os.getenv("PUBLIC_MCP_URL") or None,
    )


class BasecampMcpOAuthProvider(
    OAuthAuthorizationServerProvider[
        BasecampAuthorizationCode,
        BasecampRefreshToken,
        BasecampAccessToken,
    ]
):
    """OAuth provider for FastMCP that stores MCP tokens per Basecamp user."""

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        client = oauth_store.get_client(client_id)
        return OAuthClientInformationFull.model_validate(client) if client else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        client_id = client_info.client_id or secrets.token_urlsafe(24)
        auth_method = client_info.token_endpoint_auth_method or "none"
        client_secret = client_info.client_secret
        if auth_method != "none" and not client_secret:
            client_secret = secrets.token_urlsafe(32)
        now = oauth_store.now()
        full_info = client_info.model_copy(
            update={
                "client_id": client_id,
                "client_secret": client_secret,
                "token_endpoint_auth_method": auth_method,
                "client_id_issued_at": client_info.client_id_issued_at or now,
                "client_secret_expires_at": client_info.client_secret_expires_at or 0,
                "scope": client_info.scope or MCP_SCOPE,
            }
        )
        oauth_store.save_client(
            client_id,
            client_secret,
            full_info.model_dump(mode="json", exclude_none=True),
        )

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        state = secrets.token_urlsafe(32)
        oauth_store.save_state(
            state,
            client.client_id or "",
            _serialize_auth_params(params),
            oauth_store.now() + PENDING_STATE_TTL_SECONDS,
        )
        oauth = BasecampOAuth(redirect_uri=basecamp_redirect_uri())
        scope = os.getenv("BASECAMP_OAUTH_SCOPE")
        return oauth.get_authorization_url(state=state, scope=scope)

    async def complete_basecamp_authorization(self, state: str, code: str) -> str:
        """Finish Basecamp OAuth and return the MCP client redirect URL."""
        pending = oauth_store.pop_state(state)
        if not pending:
            raise ValueError("Invalid or expired OAuth state")

        oauth = BasecampOAuth(redirect_uri=basecamp_redirect_uri())
        token_data = oauth.exchange_code_for_token(code)
        basecamp_access_token = token_data.get("access_token")
        if not basecamp_access_token:
            raise ValueError("Basecamp did not return an access token")

        identity = oauth.get_identity(basecamp_access_token)
        accounts = _bc3_accounts(identity)
        active_account_id = choose_active_account(identity)
        if not active_account_id:
            raise ValueError("Authenticated Basecamp user does not have access to the configured account")

        user_id = extract_user_id(identity, basecamp_access_token)
        oauth_store.save_basecamp_user(
            user_id=user_id,
            identity=identity,
            accounts=accounts,
            active_account_id=active_account_id,
            access_token=basecamp_access_token,
            refresh_token=token_data.get("refresh_token"),
            expires_at=_expires_at(token_data.get("expires_in")),
        )

        auth_params = pending["auth_params"]
        mcp_code = secrets.token_urlsafe(32)
        oauth_store.save_auth_code(
            mcp_code,
            {
                "client_id": pending["client_id"],
                "user_id": user_id,
                "scopes": auth_params.get("scopes") or [MCP_SCOPE],
                "code_challenge": auth_params["code_challenge"],
                "redirect_uri": auth_params["redirect_uri"],
                "redirect_uri_provided_explicitly": auth_params.get("redirect_uri_provided_explicitly", True),
                "resource": auth_params.get("resource"),
                "expires_at": oauth_store.now() + AUTH_CODE_TTL_SECONDS,
            },
        )

        redirect_url = str(auth_params["redirect_uri"])
        from mcp.server.auth.provider import construct_redirect_uri

        return construct_redirect_uri(
            redirect_url,
            code=mcp_code,
            state=auth_params.get("state"),
        )

    async def load_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: str,
    ) -> BasecampAuthorizationCode | None:
        data = oauth_store.pop_auth_code(authorization_code)
        if not data:
            return None
        return BasecampAuthorizationCode(
            code=authorization_code,
            client_id=data["client_id"],
            user_id=data["user_id"],
            scopes=data["scopes"],
            code_challenge=data["code_challenge"],
            redirect_uri=data["redirect_uri"],
            redirect_uri_provided_explicitly=data["redirect_uri_provided_explicitly"],
            resource=data["resource"],
            expires_at=data["expires_at"],
        )

    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: BasecampAuthorizationCode,
    ) -> OAuthToken:
        return _oauth_token_for(
            authorization_code.user_id,
            client.client_id or authorization_code.client_id,
            authorization_code.scopes,
            authorization_code.resource,
        )

    async def load_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: str,
    ) -> BasecampRefreshToken | None:
        data = oauth_store.get_refresh_token(refresh_token)
        if not data:
            return None
        return BasecampRefreshToken(
            token=refresh_token,
            client_id=data["client_id"],
            user_id=data["user_id"],
            scopes=data["scopes"],
            expires_at=data["expires_at"],
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: BasecampRefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        oauth_store.revoke_oauth_token(refresh_token.token)
        return _oauth_token_for(
            refresh_token.user_id,
            client.client_id or refresh_token.client_id,
            scopes,
            None,
        )

    async def load_access_token(self, token: str) -> BasecampAccessToken | None:
        service_token = _configured_service_token(token)
        if service_token:
            return service_token

        data = oauth_store.get_access_token(token)
        if not data:
            return None
        if data["expires_at"] and int(data["expires_at"]) < int(time.time()):
            return None
        return BasecampAccessToken(
            token=token,
            client_id=data["client_id"],
            user_id=data["user_id"],
            scopes=data["scopes"],
            expires_at=data["expires_at"],
            resource=data["resource"],
        )

    async def revoke_token(self, token: BasecampAccessToken | BasecampRefreshToken) -> None:
        oauth_store.revoke_oauth_token(token.token)
