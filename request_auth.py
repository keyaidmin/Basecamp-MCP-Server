"""Request-scoped Basecamp authentication helpers for MCP tools."""

from __future__ import annotations

import logging
import os
from typing import Any

from mcp.server.auth.middleware.auth_context import get_access_token

from basecamp_client import BasecampClient
from basecamp_oauth import BasecampOAuth
from basecamp_mcp_oauth import basecamp_redirect_uri
import oauth_store
import token_storage
import auth_manager


logger = logging.getLogger(__name__)


def _configured_user_agent() -> str:
    return os.getenv("USER_AGENT") or "Basecamp MCP Server (support@example.com)"


def _is_basecamp_token_expired(user: dict[str, Any]) -> bool:
    expires_at = user.get("expires_at")
    return bool(expires_at and int(expires_at) <= oauth_store.now() + 300)


def _refresh_basecamp_user(user: dict[str, Any]) -> dict[str, Any] | None:
    refresh_token = user.get("refresh_token")
    if not refresh_token:
        return None

    oauth = BasecampOAuth(redirect_uri=basecamp_redirect_uri())
    token_data = oauth.refresh_token(refresh_token)
    access_token = token_data.get("access_token")
    if not access_token:
        return None

    oauth_store.save_basecamp_user(
        user_id=user["user_id"],
        identity=user["identity"],
        accounts=user["accounts"],
        active_account_id=user.get("active_account_id"),
        access_token=access_token,
        refresh_token=token_data.get("refresh_token") or refresh_token,
        expires_at=oauth_store.now() + int(token_data["expires_in"]) if token_data.get("expires_in") else None,
    )
    return oauth_store.get_basecamp_user(user["user_id"])


def _current_user_id() -> str | None:
    auth_token = get_access_token()
    if not auth_token:
        return None
    if hasattr(auth_token, "user_id"):
        return str(auth_token.user_id)
    return oauth_store.find_user_id_for_access_token(auth_token.token)


def get_current_basecamp_user() -> dict[str, Any] | None:
    """Return the Basecamp user bound to the current MCP request."""
    user_id = _current_user_id()
    if not user_id:
        return None
    user = oauth_store.get_basecamp_user(user_id)
    if user and _is_basecamp_token_expired(user):
        try:
            return _refresh_basecamp_user(user)
        except Exception as exc:
            logger.warning("Failed to refresh Basecamp token for user %s: %s", user_id, exc)
            return None
    return user


def get_basecamp_client() -> BasecampClient | None:
    """Create a Basecamp API client for the authenticated MCP user."""
    user = get_current_basecamp_user()
    if user:
        account_id = str(user.get("active_account_id") or "")
        configured_account_id = os.getenv("BASECAMP_ACCOUNT_ID")
        if configured_account_id and configured_account_id != account_id:
            logger.error("Authenticated user is not authorized for configured Basecamp account")
            return None
        if not account_id:
            logger.error("Authenticated user has no active Basecamp account")
            return None
        return BasecampClient(
            access_token=user["access_token"],
            account_id=account_id,
            user_agent=_configured_user_agent(),
            auth_mode="oauth",
        )

    token_data = token_storage.get_token()
    if not token_data or not token_data.get("access_token"):
        logger.error("No request OAuth context or legacy OAuth token available")
        return None
    if not auth_manager.ensure_authenticated():
        logger.error("Legacy OAuth token refresh failed")
        return None
    token_data = token_storage.get_token()
    account_id = token_data.get("account_id") or os.getenv("BASECAMP_ACCOUNT_ID")
    if not account_id:
        logger.error("Legacy OAuth token has no Basecamp account ID")
        return None
    return BasecampClient(
        access_token=token_data["access_token"],
        account_id=account_id,
        user_agent=_configured_user_agent(),
        auth_mode="oauth",
    )


def auth_error_response() -> dict[str, Any]:
    """Return a consistent MCP tool auth error."""
    if _current_user_id():
        return {
            "error": "Authentication required",
            "message": "Your Basecamp authorization is missing or expired. Reconnect the Basecamp MCP server and complete OAuth again.",
        }
    return {
        "error": "Authentication required",
        "message": "Connect this MCP server and complete the Basecamp OAuth flow before calling Basecamp tools.",
    }


def auth_status() -> dict[str, Any]:
    """Return non-secret authentication status for the current MCP user."""
    user = get_current_basecamp_user()
    if not user:
        return {"authenticated": False}
    return {
        "authenticated": True,
        "user_id": user["user_id"],
        "active_account_id": user.get("active_account_id"),
        "account_count": len(user.get("accounts", [])),
        "expires_at": user.get("expires_at"),
    }


def list_accounts() -> list[dict[str, Any]]:
    """Return available Basecamp accounts for the current MCP user."""
    user = get_current_basecamp_user()
    if not user:
        return []
    return [
        {
            "id": str(account.get("id")),
            "name": account.get("name"),
            "product": account.get("product"),
            "href": account.get("href"),
            "active": str(account.get("id")) == str(user.get("active_account_id")),
        }
        for account in user.get("accounts", [])
    ]


def set_active_account(account_id: str) -> bool:
    """Set the active Basecamp account for the current MCP user."""
    user_id = _current_user_id()
    if not user_id:
        return False
    return oauth_store.set_active_basecamp_account(user_id, account_id)
