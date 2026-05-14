"""SQLite persistence for multi-user MCP and Basecamp OAuth state."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


DEFAULT_DB_PATH = Path(__file__).with_name("oauth_state.sqlite3")
DB_PATH = Path(os.getenv("OAUTH_STORE_PATH", str(DEFAULT_DB_PATH)))

_lock = threading.RLock()


def _json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True, default=str)


def _load_json(value: str | None, default: Any) -> Any:
    if not value:
        return default
    return json.loads(value)


@contextmanager
def _connect() -> Iterator[sqlite3.Connection]:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA foreign_keys = ON")
            _initialize(conn)
            yield conn
            conn.commit()
        finally:
            conn.close()


def _initialize(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS oauth_clients (
            client_id TEXT PRIMARY KEY,
            client_secret TEXT,
            client_info TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS oauth_states (
            state TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            auth_params TEXT NOT NULL,
            expires_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS basecamp_users (
            user_id TEXT PRIMARY KEY,
            identity TEXT NOT NULL,
            accounts TEXT NOT NULL,
            active_account_id TEXT,
            access_token TEXT NOT NULL,
            refresh_token TEXT,
            expires_at INTEGER,
            updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS oauth_auth_codes (
            code TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            scopes TEXT NOT NULL,
            code_challenge TEXT NOT NULL,
            redirect_uri TEXT NOT NULL,
            redirect_uri_provided_explicitly INTEGER NOT NULL,
            resource TEXT,
            expires_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS oauth_access_tokens (
            token TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            scopes TEXT NOT NULL,
            expires_at INTEGER,
            resource TEXT,
            revoked INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
            token TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            scopes TEXT NOT NULL,
            expires_at INTEGER,
            revoked INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL
        );
        """
    )


def now() -> int:
    """Return the current Unix timestamp in seconds."""
    return int(time.time())


def save_client(client_id: str, client_secret: str | None, client_info: dict[str, Any]) -> None:
    """Persist a dynamically registered MCP OAuth client."""
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO oauth_clients (client_id, client_secret, client_info, created_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(client_id) DO UPDATE SET
                client_secret = excluded.client_secret,
                client_info = excluded.client_info
            """,
            (client_id, client_secret, _json(client_info), now()),
        )


def get_client(client_id: str) -> dict[str, Any] | None:
    """Return a registered MCP OAuth client by ID."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT client_info FROM oauth_clients WHERE client_id = ?",
            (client_id,),
        ).fetchone()
    return _load_json(row["client_info"], None) if row else None


def save_state(state: str, client_id: str, auth_params: dict[str, Any], expires_at: int) -> None:
    """Persist a pending Basecamp OAuth redirect state."""
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO oauth_states (state, client_id, auth_params, expires_at)
            VALUES (?, ?, ?, ?)
            """,
            (state, client_id, _json(auth_params), expires_at),
        )


def pop_state(state: str) -> dict[str, Any] | None:
    """Load and delete a pending OAuth state."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM oauth_states WHERE state = ?",
            (state,),
        ).fetchone()
        conn.execute("DELETE FROM oauth_states WHERE state = ?", (state,))
    if not row or int(row["expires_at"]) < now():
        return None
    return {
        "state": row["state"],
        "client_id": row["client_id"],
        "auth_params": _load_json(row["auth_params"], {}),
        "expires_at": row["expires_at"],
    }


def save_basecamp_user(
    *,
    user_id: str,
    identity: dict[str, Any],
    accounts: list[dict[str, Any]],
    active_account_id: str | None,
    access_token: str,
    refresh_token: str | None,
    expires_at: int | None,
) -> None:
    """Persist Basecamp OAuth credentials for one authenticated Basecamp user."""
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO basecamp_users (
                user_id, identity, accounts, active_account_id,
                access_token, refresh_token, expires_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                identity = excluded.identity,
                accounts = excluded.accounts,
                active_account_id = excluded.active_account_id,
                access_token = excluded.access_token,
                refresh_token = excluded.refresh_token,
                expires_at = excluded.expires_at,
                updated_at = excluded.updated_at
            """,
            (
                user_id,
                _json(identity),
                _json(accounts),
                active_account_id,
                access_token,
                refresh_token,
                expires_at,
                now(),
            ),
        )


def get_basecamp_user(user_id: str) -> dict[str, Any] | None:
    """Return stored Basecamp OAuth credentials for a user."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM basecamp_users WHERE user_id = ?",
            (user_id,),
        ).fetchone()
    if not row:
        return None
    return {
        "user_id": row["user_id"],
        "identity": _load_json(row["identity"], {}),
        "accounts": _load_json(row["accounts"], []),
        "active_account_id": row["active_account_id"],
        "access_token": row["access_token"],
        "refresh_token": row["refresh_token"],
        "expires_at": row["expires_at"],
        "updated_at": row["updated_at"],
    }


def set_active_basecamp_account(user_id: str, account_id: str) -> bool:
    """Set the active Basecamp account for a user if that account is available."""
    user = get_basecamp_user(user_id)
    if not user:
        return False
    allowed_ids = {str(account.get("id")) for account in user["accounts"]}
    if str(account_id) not in allowed_ids:
        return False
    with _connect() as conn:
        conn.execute(
            "UPDATE basecamp_users SET active_account_id = ?, updated_at = ? WHERE user_id = ?",
            (str(account_id), now(), user_id),
        )
    return True


def save_auth_code(code: str, data: dict[str, Any]) -> None:
    """Persist an MCP authorization code."""
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO oauth_auth_codes (
                code, client_id, user_id, scopes, code_challenge,
                redirect_uri, redirect_uri_provided_explicitly, resource, expires_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                code,
                data["client_id"],
                data["user_id"],
                _json(data.get("scopes", [])),
                data["code_challenge"],
                data["redirect_uri"],
                1 if data.get("redirect_uri_provided_explicitly") else 0,
                data.get("resource"),
                data["expires_at"],
            ),
        )


def pop_auth_code(code: str) -> dict[str, Any] | None:
    """Load and delete an MCP authorization code."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM oauth_auth_codes WHERE code = ?",
            (code,),
        ).fetchone()
        conn.execute("DELETE FROM oauth_auth_codes WHERE code = ?", (code,))
    if not row:
        return None
    return {
        "code": row["code"],
        "client_id": row["client_id"],
        "user_id": row["user_id"],
        "scopes": _load_json(row["scopes"], []),
        "code_challenge": row["code_challenge"],
        "redirect_uri": row["redirect_uri"],
        "redirect_uri_provided_explicitly": bool(row["redirect_uri_provided_explicitly"]),
        "resource": row["resource"],
        "expires_at": row["expires_at"],
    }


def save_access_token(token: str, data: dict[str, Any]) -> None:
    """Persist an MCP bearer access token."""
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO oauth_access_tokens (
                token, client_id, user_id, scopes, expires_at, resource, revoked, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, 0, ?)
            """,
            (
                token,
                data["client_id"],
                data["user_id"],
                _json(data.get("scopes", [])),
                data.get("expires_at"),
                data.get("resource"),
                now(),
            ),
        )


def get_access_token(token: str) -> dict[str, Any] | None:
    """Return an active MCP bearer token."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM oauth_access_tokens WHERE token = ? AND revoked = 0",
            (token,),
        ).fetchone()
    if not row:
        return None
    return {
        "token": row["token"],
        "client_id": row["client_id"],
        "user_id": row["user_id"],
        "scopes": _load_json(row["scopes"], []),
        "expires_at": row["expires_at"],
        "resource": row["resource"],
    }


def save_refresh_token(token: str, data: dict[str, Any]) -> None:
    """Persist an MCP refresh token."""
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO oauth_refresh_tokens (
                token, client_id, user_id, scopes, expires_at, revoked, created_at
            )
            VALUES (?, ?, ?, ?, ?, 0, ?)
            """,
            (
                token,
                data["client_id"],
                data["user_id"],
                _json(data.get("scopes", [])),
                data.get("expires_at"),
                now(),
            ),
        )


def get_refresh_token(token: str) -> dict[str, Any] | None:
    """Return an active MCP refresh token."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM oauth_refresh_tokens WHERE token = ? AND revoked = 0",
            (token,),
        ).fetchone()
    if not row:
        return None
    return {
        "token": row["token"],
        "client_id": row["client_id"],
        "user_id": row["user_id"],
        "scopes": _load_json(row["scopes"], []),
        "expires_at": row["expires_at"],
    }


def revoke_oauth_token(token: str) -> None:
    """Revoke an MCP access or refresh token string."""
    with _connect() as conn:
        conn.execute("UPDATE oauth_access_tokens SET revoked = 1 WHERE token = ?", (token,))
        conn.execute("UPDATE oauth_refresh_tokens SET revoked = 1 WHERE token = ?", (token,))


def find_user_id_for_access_token(token: str) -> str | None:
    """Return the Basecamp user ID bound to an active MCP access token."""
    data = get_access_token(token)
    return data["user_id"] if data else None


def clear_all() -> None:
    """Remove all OAuth state. Intended for tests."""
    with _connect() as conn:
        for table in (
            "oauth_clients",
            "oauth_states",
            "basecamp_users",
            "oauth_auth_codes",
            "oauth_access_tokens",
            "oauth_refresh_tokens",
        ):
            conn.execute(f"DELETE FROM {table}")
