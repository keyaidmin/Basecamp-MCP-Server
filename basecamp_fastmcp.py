#!/usr/bin/env python3
"""
FastMCP server for Basecamp integration.

This server implements the MCP (Model Context Protocol) using the official
Anthropic FastMCP framework, replacing the custom JSON-RPC implementation.
"""

import logging
import os
import sys
import hmac
import html
from typing import Any, Dict, List, Optional
import anyio
import httpx
from mcp.server.fastmcp import FastMCP
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse

# Import existing business logic
from basecamp_client import BasecampClient
from search_utils import BasecampSearch
from todo_context import compact_comment, compact_comments, compact_todo, compact_todos
from basecamp_context import load_or_create_summary
from status_update import select_recent_comments
import token_storage
import auth_manager
import request_auth
import oauth_store
from basecamp_mcp_oauth import (
    BasecampMcpOAuthProvider,
    MCP_SCOPE,
    create_service_reconnect_authorization_url,
    public_base_url,
)
from dotenv import load_dotenv

# Determine project root (directory containing this script)
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
DOTENV_PATH = os.path.join(PROJECT_ROOT, '.env')
load_dotenv(DOTENV_PATH)

# Set up logging to file AND stderr (following MCP best practices)
LOG_FILE_PATH = os.path.join(PROJECT_ROOT, 'basecamp_fastmcp.log')
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE_PATH),
        logging.StreamHandler(sys.stderr)  # Critical: log to stderr, not stdout
    ]
)
logger = logging.getLogger('basecamp_fastmcp')
SERVICE_OAUTH_BROWSER_USER_EMAIL = "aibot@key.study"

if os.getenv("ALLOW_INSECURE_OAUTH", "").lower() in {"1", "true", "yes"}:
    import mcp.server.auth.routes as auth_routes

    logger.warning("ALLOW_INSECURE_OAUTH is enabled; OAuth metadata will be served over HTTP")
    auth_routes.validate_issuer_url = lambda url: None


def _auth_settings() -> AuthSettings:
    base_url = public_base_url()
    resource_server_url = os.getenv("PUBLIC_MCP_URL", "").strip().rstrip("/")
    if not resource_server_url:
        resource_server_url = base_url if "/mcp" in base_url else f"{base_url}/mcp"
    return AuthSettings(
        issuer_url=base_url,
        resource_server_url=resource_server_url,
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            valid_scopes=[MCP_SCOPE],
            default_scopes=[MCP_SCOPE],
        ),
        revocation_options=RevocationOptions(enabled=True),
        required_scopes=[MCP_SCOPE],
    )


oauth_provider = BasecampMcpOAuthProvider()

# Initialize FastMCP server
mcp = FastMCP(
    "basecamp",
    auth_server_provider=oauth_provider,
    auth=_auth_settings(),
    host=os.getenv("MCP_HOST", "127.0.0.1"),
    port=int(os.getenv("MCP_PORT", "8051")),
    streamable_http_path="/mcp",
)


@mcp.custom_route("/health", methods=["GET"])
async def health_check(request: Request):
    """Report that the FastMCP HTTP server is running."""
    return JSONResponse({"status": "ok"})


def _service_token_from_request(request: Request) -> str:
    authorization = request.headers.get("authorization", "")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer":
        return ""
    return token.strip()


def _is_service_api_request(request: Request) -> bool:
    configured_token = os.getenv("BASECAMP_MCP_AUTH_TOKEN", "").strip()
    token = _service_token_from_request(request)
    return bool(configured_token and token and hmac.compare_digest(token, configured_token))


def _service_user_id() -> str:
    configured_user_id = os.getenv("BASECAMP_MCP_AUTH_USER_ID", "").strip()
    if configured_user_id:
        return configured_user_id
    account_id = _service_account_id()
    user = oauth_store.find_basecamp_user_for_account(account_id) if account_id else None
    return str(user["user_id"]) if user else ""


def _service_account_id() -> str:
    return (os.getenv("BASECAMP_MCP_AUTH_ACCOUNT_ID") or os.getenv("BASECAMP_ACCOUNT_ID") or "").strip()


def _service_api_unauthorized_response() -> JSONResponse:
    return JSONResponse(
        {"error": "Unauthorized", "message": "Valid BASECAMP_MCP_AUTH_TOKEN bearer token required."},
        status_code=401,
    )


def _service_basecamp_user() -> dict[str, Any] | None:
    user_id = _service_user_id()
    return oauth_store.get_basecamp_user(user_id) if user_id else None


def _basecamp_auth_status_payload(refresh: bool = False) -> dict[str, Any]:
    user_id = _service_user_id()
    user = oauth_store.get_basecamp_user(user_id) if user_id else None
    refresh_error = None
    if refresh and user and request_auth._is_basecamp_token_expired(user):
        try:
            user = request_auth._refresh_basecamp_user(user)
        except Exception as exc:
            logger.warning("Service Basecamp OAuth refresh failed for user %s: %s", user_id, exc)
            refresh_error = str(exc)

    expires_at = user.get("expires_at") if user else None
    expired = bool(expires_at and int(expires_at) <= oauth_store.now())
    expires_soon = bool(expires_at and int(expires_at) <= oauth_store.now() + 300)
    return {
        "status": "success",
        "service_user_id": user_id or None,
        "service_account_id": _service_account_id() or None,
        "basecamp_user_found": bool(user),
        "authenticated": bool(user and not expired),
        "active_account_id": user.get("active_account_id") if user else None,
        "account_count": len(user.get("accounts", [])) if user else 0,
        "expires_at": expires_at,
        "expired": expired,
        "expires_soon": expires_soon,
        "has_refresh_token": bool(user and user.get("refresh_token")),
        "refresh_error": refresh_error,
    }


def _service_basecamp_client() -> BasecampClient | None:
    user = _service_basecamp_user()
    if not user:
        return None
    if request_auth._is_basecamp_token_expired(user):
        user = request_auth._refresh_basecamp_user(user)
    if not user:
        return None
    account_id = str(user.get("active_account_id") or "")
    if not account_id:
        return None
    return BasecampClient(
        access_token=user["access_token"],
        account_id=account_id,
        user_agent=os.getenv("USER_AGENT") or "Basecamp MCP Server (support@example.com)",
        auth_mode="oauth",
    )


def _service_auth_url_payload() -> dict[str, Any]:
    configured_user_id = os.getenv("BASECAMP_MCP_AUTH_USER_ID", "").strip()
    account_id = _service_account_id()
    if not configured_user_id and not account_id:
        raise ValueError("BASECAMP_MCP_AUTH_USER_ID or BASECAMP_MCP_AUTH_ACCOUNT_ID is required.")

    authorization_url = create_service_reconnect_authorization_url(
        user_id=configured_user_id or None,
        account_id=account_id or None,
    )
    return {
        "status": "success",
        "authorization_url": authorization_url,
        "service_user_id": configured_user_id or None,
        "resolved_user_id": _service_user_id() or None,
        "service_account_id": account_id or None,
        "required_browser_user": SERVICE_OAUTH_BROWSER_USER_EMAIL,
        "callback_url": os.getenv("BASECAMP_REDIRECT_URI") or f"{public_base_url()}/basecamp/oauth/callback",
        "instructions": (
            f"Open authorization_url in a browser where {SERVICE_OAUTH_BROWSER_USER_EMAIL} "
            "is logged into Basecamp and has access to the configured account."
        ),
    }


def _oauth_result_page(title: str, message: str, status_code: int = 200, details: str | None = None) -> HTMLResponse:
    escaped_title = html.escape(title)
    escaped_message = html.escape(message)
    escaped_details = html.escape(details or "")
    detail_html = f"<pre>{escaped_details}</pre>" if details else ""
    return HTMLResponse(
        f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <title>{escaped_title}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; background: #f6f7f9; color: #17202a; }}
    main {{ max-width: 720px; margin: 10vh auto; padding: 32px; background: white; border: 1px solid #d9dee7; border-radius: 8px; }}
    h1 {{ font-size: 24px; margin: 0 0 16px; }}
    p {{ line-height: 1.55; }}
    code {{ background: #eef1f5; padding: 2px 5px; border-radius: 4px; }}
    pre {{ white-space: pre-wrap; background: #f0f2f5; padding: 12px; border-radius: 6px; }}
  </style>
</head>
<body>
  <main>
    <h1>{escaped_title}</h1>
    <p>{escaped_message}</p>
    <p>For service access recovery, open the OAuth URL in a browser where <code>{SERVICE_OAUTH_BROWSER_USER_EMAIL}</code> is logged into Basecamp and has access to account <code>{html.escape(_service_account_id() or "configured account")}</code>.</p>
    {detail_html}
  </main>
</body>
</html>""",
        status_code=status_code,
    )


@mcp.custom_route("/basecamp/api/auth/status", methods=["GET"])
async def service_basecamp_auth_status(request: Request):
    """Report Basecamp OAuth state for the service-token-bound user."""
    if not _is_service_api_request(request):
        return _service_api_unauthorized_response()
    refresh = request.query_params.get("refresh", "").lower() in {"1", "true", "yes"}
    return JSONResponse(_basecamp_auth_status_payload(refresh=refresh))


@mcp.custom_route("/basecamp/api/auth/url", methods=["GET"])
async def service_basecamp_auth_url(request: Request):
    """Return a browser URL that reconnects Basecamp OAuth for API users."""
    if not _is_service_api_request(request):
        return _service_api_unauthorized_response()

    try:
        payload = _service_auth_url_payload()
    except Exception as exc:
        logger.exception("Failed to create Basecamp service reconnect URL")
        return JSONResponse({"error": "Authorization URL error", "message": str(exc)}, status_code=500)

    return JSONResponse(payload)


@mcp.custom_route("/basecamp/api/webhooks/register-url", methods=["GET"])
async def service_webhook_registration_url(request: Request):
    """Return direct Basecamp API details for registering a webhook."""
    if not _is_service_api_request(request):
        return _service_api_unauthorized_response()

    project_id = request.query_params.get("project_id")
    if not project_id:
        return JSONResponse({"error": "Invalid input", "message": "project_id is required."}, status_code=400)

    user = _service_basecamp_user()
    account_id = str(user.get("active_account_id") or os.getenv("BASECAMP_ACCOUNT_ID") or "") if user else ""
    if not account_id:
        return JSONResponse(
            {"error": "Authentication required", "message": "Reconnect Basecamp OAuth before registering webhooks."},
            status_code=409,
        )

    return JSONResponse(
        {
            "status": "success",
            "method": "POST",
            "url": f"https://3.basecampapi.com/{account_id}/buckets/{project_id}/webhooks.json",
            "mcp_api_url": f"{public_base_url()}/basecamp/api/webhooks",
            "headers": {
                "Authorization": "Bearer <Basecamp OAuth access token>",
                "Content-Type": "application/json",
                "User-Agent": os.getenv("USER_AGENT") or "<configured USER_AGENT>",
            },
            "body_schema": {
                "payload_url": "https://your-service.example.com/basecamp/webhook",
                "types": ["Todo", "Todolist", "Comment"],
            },
        }
    )


@mcp.custom_route("/basecamp/api/webhooks", methods=["POST"])
async def service_create_webhook(request: Request):
    """Register a Basecamp webhook through the service-token API."""
    if not _is_service_api_request(request):
        return _service_api_unauthorized_response()

    try:
        payload = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid input", "message": "JSON body required."}, status_code=400)

    project_id = str(payload.get("project_id") or "").strip()
    payload_url = str(payload.get("payload_url") or "").strip()
    types = payload.get("types")
    if not project_id or not payload_url:
        return JSONResponse(
            {"error": "Invalid input", "message": "project_id and payload_url are required."},
            status_code=400,
        )
    if types is not None and not isinstance(types, list):
        return JSONResponse({"error": "Invalid input", "message": "types must be a list when provided."}, status_code=400)

    try:
        client = _service_basecamp_client()
        if not client:
            return JSONResponse(
                {"error": "Authentication required", "message": "Reconnect Basecamp OAuth before registering webhooks."},
                status_code=409,
            )
        hook = await _run_sync(client.create_webhook, project_id, payload_url, types)
        return JSONResponse({"status": "success", "webhook": hook}, status_code=201)
    except Exception as exc:
        logger.exception("Service webhook registration failed")
        return JSONResponse({"error": "Execution error", "message": str(exc)}, status_code=400)


@mcp.custom_route("/basecamp/oauth/callback", methods=["GET"])
async def basecamp_oauth_callback(request: Request):
    """Complete the delegated Basecamp OAuth flow for MCP authorization."""
    error = request.query_params.get("error")
    if error:
        return _oauth_result_page(
            "Basecamp OAuth Failed",
            "Basecamp rejected the authorization request.",
            status_code=400,
            details=error,
        )

    state = request.query_params.get("state")
    code = request.query_params.get("code")
    if not state or not code:
        return _oauth_result_page(
            "Basecamp OAuth Failed",
            "The callback was missing an OAuth state or code. Generate a new recovery URL from the MCP tool and try again.",
            status_code=400,
        )

    try:
        redirect_url = await oauth_provider.complete_basecamp_authorization(state, code)
        if redirect_url == f"{public_base_url()}/health":
            return _oauth_result_page(
                "Basecamp OAuth Reconnected",
                "The MCP service account authorization was refreshed successfully. API clients can retry their Basecamp request now.",
            )
        return RedirectResponse(redirect_url, status_code=302)
    except Exception as exc:
        logger.exception("Basecamp OAuth callback failed")
        return _oauth_result_page(
            "Basecamp OAuth Failed",
            "The OAuth callback could not refresh the MCP service account authorization.",
            status_code=400,
            details=str(exc),
        )

# Auth helper functions (reused from original server)
def _get_basecamp_client() -> Optional[BasecampClient]:
    """Get authenticated Basecamp client (sync version from original server)."""
    return request_auth.get_basecamp_client()

def _get_auth_error_response() -> Dict[str, Any]:
    """Return consistent auth error response."""
    return request_auth.auth_error_response()

async def _run_sync(func, *args, **kwargs):
    """Wrapper to run synchronous functions in thread pool."""
    return await anyio.to_thread.run_sync(func, *args, **kwargs)

# Core MCP Tools - Starting with essential ones from original server

@mcp.tool()
async def get_auth_status() -> Dict[str, Any]:
    """Get authentication status for the current Basecamp MCP user."""
    return {"status": "success", "auth": request_auth.auth_status()}


@mcp.tool()
async def get_basecamp_service_auth_status(refresh: bool = True) -> Dict[str, Any]:
    """Get Basecamp service-account OAuth status for API clients.

    Args:
        refresh: Try refreshing Basecamp OAuth before returning status.
    """
    return _basecamp_auth_status_payload(refresh=refresh)


@mcp.tool()
async def get_basecamp_auth_recovery_url() -> Dict[str, Any]:
    """Get a browser OAuth URL to recover Basecamp service-account access.

    Open the returned authorization_url in a browser where aibot@key.study is
    logged into Basecamp and has access to the configured service account.
    """
    return _service_auth_url_payload()


@mcp.tool()
async def list_basecamp_accounts() -> Dict[str, Any]:
    """List Basecamp accounts available to the current authenticated user."""
    accounts = request_auth.list_accounts()
    if not accounts:
        return _get_auth_error_response()
    return {"status": "success", "accounts": accounts, "count": len(accounts)}


@mcp.tool()
async def set_active_basecamp_account(account_id: str) -> Dict[str, Any]:
    """Set the active Basecamp account for future tool calls.

    Args:
        account_id: The Basecamp account ID returned by list_basecamp_accounts
    """
    if request_auth.set_active_account(account_id):
        return {
            "status": "success",
            "message": f"Active Basecamp account set to {account_id}",
        }
    return {
        "error": "Invalid account",
        "message": "The current authenticated user does not have access to that Basecamp account.",
    }


@mcp.tool()
async def get_projects() -> Dict[str, Any]:
    """Get all Basecamp projects."""
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        projects = await _run_sync(client.get_projects)
        return {
            "status": "success",
            "projects": projects,
            "count": len(projects)
        }
    except Exception as e:
        logger.error(f"Error getting projects: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def get_project(project_id: str) -> Dict[str, Any]:
    """Get details for a specific project.
    
    Args:
        project_id: The project ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        project = await _run_sync(client.get_project, project_id)
        return {
            "status": "success",
            "project": project
        }
    except Exception as e:
        logger.error(f"Error getting project {project_id}: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def search_basecamp(query: str, project_id: Optional[str] = None) -> Dict[str, Any]:
    """Search Basecamp todos/comments by keyword. Todo matches are verified by fetching project-scoped todo feeds and filtering locally before using the official search API as a fallback.
    
    Args:
        query: Search query (e.g. 'CV recognition', task name, keyword)
        project_id: Optional project ID to limit search scope
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    try:
        search = BasecampSearch(client=client)
        bucket_id = int(project_id) if project_id else None
        recordings = await _run_sync(
            lambda: search.search_recordings_api_todos_and_comments(
                query, bucket_id=bucket_id, max_results=10
            )
        )
        if isinstance(recordings, list):
            recordings = compact_todos(recordings[:10])
        count = len(recordings) if isinstance(recordings, list) else 0
        # Group by type for clients that expect projects/todos/messages (top 3 relevance-ranked)
        results = {"recordings": recordings, "count": count}
        if isinstance(recordings, list):
            results["todos"] = [r for r in recordings if r.get("type") == "Todo"]
            results["messages"] = [r for r in recordings if r.get("type") == "Message"]
            results["comments"] = [r for r in recordings if r.get("type") == "Comment"]
            results["projects"] = []  # API returns recordings, not project list; use bucket in each item
        return {
            "status": "success",
            "query": query,
            "results": results,
            "count": count,
        }
    except Exception as e:
        logger.error(f"Error searching Basecamp: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def get_todolists(project_id: str) -> Dict[str, Any]:
    """Get todo lists for a project.
    
    Args:
        project_id: The project ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        todolists = await _run_sync(client.get_todolists, project_id)
        return {
            "status": "success",
            "todolists": todolists,
            "count": len(todolists)
        }
    except Exception as e:
        logger.error(f"Error getting todolists: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def get_todos(project_id: str, todolist_id: str) -> Dict[str, Any]:
    """Get todos from a todo list.
    
    Args:
        project_id: Project ID
        todolist_id: The todo list ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        todos = await _run_sync(client.get_todos, project_id, todolist_id)
        todos = compact_todos(todos)
        return {
            "status": "success",
            "todos": todos,
            "count": len(todos)
        }
    except Exception as e:
        logger.error(f"Error getting todos: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def get_project_todos(project_id: str, status: str = "active", limit: int = 50) -> Dict[str, Any]:
    """Get todos inside a project, newest updated first, with compact task context.

    Args:
        project_id: Project ID
        status: Recording status to request from Basecamp, usually active
        limit: Maximum number of todos to return
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()

    try:
        safe_limit = max(1, min(int(limit), 100))
        todos = await _run_sync(client.get_project_todos, project_id, status, safe_limit)
        todos = compact_todos(todos)
        return {
            "status": "success",
            "project_id": project_id,
            "todos": todos,
            "count": len(todos)
        }
    except Exception as e:
        logger.error(f"Error getting project todos for {project_id}: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }


@mcp.tool()
async def get_project_status_update(
    project_id: str,
    todo_limit: int = 10,
    comments_per_todo: int = 5,
    days: int = 7,
) -> Dict[str, Any]:
    """Get compact project status from recent updated todos and their recent comments.

    Args:
        project_id: Project ID
        todo_limit: Maximum number of recently updated todos to inspect
        comments_per_todo: Recent comments returned per todo
        days: Comment recency window; falls back to latest comments when none are in this window
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()

    try:
        safe_todo_limit = max(1, min(int(todo_limit), 25))
        safe_comment_limit = max(1, min(int(comments_per_todo), 10))
        safe_days = max(1, min(int(days), 30))

        raw_todos = await _run_sync(client.get_project_todos, project_id, "active", safe_todo_limit)
        todos = compact_todos(raw_todos)
        updates = []

        for todo in todos:
            todo_id = str(todo.get("id"))
            comment_result = await _run_sync(client.get_all_comments, project_id, todo_id)
            compacted_comments = compact_comments(comment_result.get("comments", []))
            selected_comments = select_recent_comments(
                compacted_comments,
                days=safe_days,
                fallback_count=safe_comment_limit,
            )
            context = load_or_create_summary(project_id, todo_id, compacted_comments)
            updates.append({
                "todo": todo,
                "comment_context": {
                    "summary": context["summary"],
                    "cached": context["cached"],
                    "latest_comment_at": context["latest_comment_at"],
                    "total_fetched_comments": len(compacted_comments),
                    "total_comments": comment_result.get("total_count"),
                    "has_more_comments": comment_result.get("has_more", False),
                    "returned_recent_comments": len(selected_comments),
                },
                "recent_comments": selected_comments,
            })

        return {
            "status": "success",
            "project_id": project_id,
            "todo_count": len(updates),
            "days": safe_days,
            "updates": updates,
        }
    except Exception as e:
        logger.error(f"Error getting project status update for {project_id}: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }


@mcp.tool()
async def prepare_todo_context(
    project_id: str,
    todo_id: str,
    force_refresh: bool = False,
    max_comment_pages: int = 4,
) -> Dict[str, Any]:
    """Prepare and cache a compact summary of a Basecamp todo's full comment context.

    Use this tool when the user asks for a task/todo summary, asks what happened
    in a todo, or needs the full task context without reading all comments again.

    Args:
        project_id: Project ID
        todo_id: Todo ID
        force_refresh: Rebuild the cached summary even when comments are unchanged
        max_comment_pages: Maximum Basecamp comment pages to fetch for summary preparation
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()

    try:
        safe_max_pages = max(1, min(int(max_comment_pages), 10))
        raw_todo = await _run_sync(client.get_todo, project_id, todo_id)
        todo = compact_todo(raw_todo)
        comment_result = await _run_sync(client.get_all_comments, project_id, todo_id, safe_max_pages)
        comments = compact_comments(comment_result.get("comments", []))
        context = load_or_create_summary(
            project_id,
            todo_id,
            comments,
            force_refresh=force_refresh,
            total_comments=comment_result.get("total_count"),
            fetched_comments=len(comments),
            has_more_comments=comment_result.get("has_more", False),
        )
        return {
            "status": "success",
            "project_id": project_id,
            "todo_id": todo_id,
            "todo": todo,
            "context": {
                "summary": context["summary"],
                "cached": context["cached"],
                "cache_created_at": context["cache_created_at"],
                "cache_updated_at": context["cache_updated_at"],
                "latest_comment_at": context["latest_comment_at"],
                "total_comments": context["total_comments"],
                "total_fetched_comments": context["fetched_comments"],
                "has_more_comments": context["has_more_comments"],
            },
        }
    except Exception as e:
        logger.error(f"Error preparing todo context for {todo_id}: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def get_todo(project_id: str, todo_id: str) -> Dict[str, Any]:
    """Get a single todo item by its ID.

    Args:
        project_id: Project ID
        todo_id: The todo ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()

    try:
        todo = await _run_sync(client.get_todo, project_id, todo_id)
        return {
            "status": "success",
            "todo": compact_todo(todo)
        }
    except Exception as e:
        logger.error(f"Error getting todo {todo_id}: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def create_todo(project_id: str, todolist_id: str, content: str, 
                     description: Optional[str] = None, 
                     assignee_ids: Optional[List[str]] = None,
                     completion_subscriber_ids: Optional[List[str]] = None, 
                     notify: bool = False, 
                     due_on: Optional[str] = None, 
                     starts_on: Optional[str] = None) -> Dict[str, Any]:
    """Create a new todo item in a todo list.
    
    Args:
        project_id: Project ID
        todolist_id: The todo list ID
        content: The todo item's text (required)
        description: HTML description of the todo
        assignee_ids: List of person IDs to assign
        completion_subscriber_ids: List of person IDs to notify on completion
        notify: Whether to notify assignees
        due_on: Due date in YYYY-MM-DD format
        starts_on: Start date in YYYY-MM-DD format
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        # Use lambda to properly handle keyword arguments
        todo = await _run_sync(
            lambda: client.create_todo(
                project_id, todolist_id, content,
                description=description,
                assignee_ids=assignee_ids,
                completion_subscriber_ids=completion_subscriber_ids,
                notify=notify,
                due_on=due_on,
                starts_on=starts_on
            )
        )
        return {
            "status": "success",
            "todo": compact_todo(todo),
            "message": f"Todo '{content}' created successfully"
        }
    except Exception as e:
        logger.error(f"Error creating todo: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def update_todo(project_id: str, todo_id: str, 
                     content: Optional[str] = None,
                     description: Optional[str] = None, 
                     assignee_ids: Optional[List[str]] = None,
                     completion_subscriber_ids: Optional[List[str]] = None,
                     notify: Optional[bool] = None,
                     due_on: Optional[str] = None, 
                     starts_on: Optional[str] = None) -> Dict[str, Any]:
    """Update an existing todo item.
    
    Args:
        project_id: Project ID
        todo_id: The todo ID
        content: The todo item's text
        description: HTML description of the todo
        assignee_ids: List of person IDs to assign
        completion_subscriber_ids: List of person IDs to notify on completion
        due_on: Due date in YYYY-MM-DD format
        starts_on: Start date in YYYY-MM-DD format
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        # Guard against no-op updates
        if all(v is None for v in [content, description, assignee_ids,
                                   completion_subscriber_ids, notify,
                                   due_on, starts_on]):
            return {
                "error": "Invalid input",
                "message": "At least one field to update must be provided"
            }
        # Use lambda to properly handle keyword arguments
        todo = await _run_sync(
            lambda: client.update_todo(
                project_id, todo_id,
                content=content,
                description=description,
                assignee_ids=assignee_ids,
                completion_subscriber_ids=completion_subscriber_ids,
                notify=notify,
                due_on=due_on,
                starts_on=starts_on
            )
        )
        return {
            "status": "success",
            "todo": compact_todo(todo),
            "message": "Todo updated successfully"
        }
    except Exception as e:
        logger.error(f"Error updating todo: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def delete_todo(project_id: str, todo_id: str) -> Dict[str, Any]:
    """Move a todo item to the trash.

    Trashed todos can be recovered from the Basecamp web UI within 30 days.

    Args:
        project_id: Project ID
        todo_id: The todo ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()

    try:
        await _run_sync(client.delete_todo, project_id, todo_id)
        return {
            "status": "success",
            "message": "Todo moved to trash"
        }
    except Exception as e:
        logger.error(f"Error trashing todo: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def complete_todo(project_id: str, todo_id: str) -> Dict[str, Any]:
    """Mark a todo item as complete.
    
    Args:
        project_id: Project ID
        todo_id: The todo ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        completion = await _run_sync(client.complete_todo, project_id, todo_id)
        return {
            "status": "success",
            "completion": completion,
            "message": "Todo marked as complete"
        }
    except Exception as e:
        logger.error(f"Error completing todo: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def uncomplete_todo(project_id: str, todo_id: str) -> Dict[str, Any]:
    """Mark a todo item as incomplete.
    
    Args:
        project_id: Project ID
        todo_id: The todo ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        await _run_sync(client.uncomplete_todo, project_id, todo_id)
        return {
            "status": "success",
            "message": "Todo marked as incomplete"
        }
    except Exception as e:
        logger.error(f"Error uncompleting todo: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def archive_todo(project_id: str, todo_id: str) -> Dict[str, Any]:
    """Archive a todo item.

    Archived todos are hidden from the active list but remain accessible
    via the Basecamp web UI.

    Args:
        project_id: Project ID
        todo_id: The todo ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()

    try:
        await _run_sync(client.archive_todo, project_id, todo_id)
        return {"status": "success", "message": f"Todo {todo_id} archived"}
    except Exception as e:
        logger.error(f"Error archiving todo {todo_id}: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {"error": "OAuth token expired", "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."}
        return {"error": "Execution error", "message": str(e)}


@mcp.tool()
async def reposition_todo(
    project_id: str,
    todo_id: str,
    position: int,
    parent_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Reposition a todo within its list, or move it to another list or group.

    Args:
        project_id: The project ID
        todo_id: The todo ID
        position: New 1-based position within the target list
        parent_id: ID of the target todolist or group to move the todo into.
                   Omit to keep the todo in its current list and only change position.
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()

    if position < 1:
        return {"error": "Invalid input", "message": "position must be >= 1"}

    try:
        await _run_sync(
            lambda: client.reposition_todo(project_id, todo_id, position, parent_id)
        )
        return {"status": "success", "message": f"Todo {todo_id} moved to position {position}"}
    except Exception as e:
        logger.error(f"Error repositioning todo {todo_id}: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {"error": "OAuth token expired", "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."}
        return {"error": "Execution error", "message": str(e)}


@mcp.tool()
async def global_search(query: str) -> Dict[str, Any]:
    """Search Basecamp todos/comments by keyword across projects. Todo matches are verified by fetching project-scoped todo feeds and filtering locally.
    
    Args:
        query: Search query (e.g. 'CV recognition', task name, or keyword)
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    try:
        search = BasecampSearch(client=client)
        recordings = await _run_sync(
            lambda: search.search_recordings_api_todos_and_comments(query, max_results=10)
        )
        if isinstance(recordings, list):
            recordings = compact_todos(recordings[:10])
        count = len(recordings) if isinstance(recordings, list) else 0
        return {
            "status": "success",
            "query": query,
            "recordings": recordings,
            "count": count,
        }
    except Exception as e:
        logger.error(f"Error in global search: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }


@mcp.tool()
async def get_search_metadata() -> Dict[str, Any]:
    """Get valid filter options for Basecamp search (recording types, file types).
    Use these type keys with search_recordings when filtering (e.g. type='Todo' for to-dos).
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    try:
        search = BasecampSearch(client=client)
        metadata = await _run_sync(search.get_search_metadata)
        return {"status": "success", "metadata": metadata}
    except Exception as e:
        logger.error(f"Error getting search metadata: {e}")
        return {"error": "Execution error", "message": str(e)}


@mcp.tool()
async def search_recordings(
    query: str,
    type: Optional[str] = None,
    bucket_id: Optional[str] = None,
    creator_id: Optional[str] = None,
    file_type: Optional[str] = None,
    exclude_chat: Optional[bool] = None,
    page: int = 1,
    per_page: int = 10,
) -> Dict[str, Any]:
    """Search across Basecamp content. Todo searches use verified project-scoped todo feeds; other types use the official API with local query/type filtering.
    Returns at most 10 recordings (to-dos, messages, cards, documents, comments, etc.).
    Use get_search_metadata to see valid type/file_type filter values (e.g. Todo, Message, Kanban::Card).
    
    Args:
        query: Search query string (required)
        type: Optional recording type filter (e.g. 'Todo', 'Message', 'Kanban::Card')
        bucket_id: Optional project ID to limit search
        creator_id: Optional person ID to filter by creator
        file_type: Optional file type (e.g. 'PDF', 'Image')
        exclude_chat: Set true to exclude chat results
        page: Page number (default 1)
        per_page: Results per page (default 10; response is capped at 10)
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    try:
        search = BasecampSearch(client=client)
        limit = min(per_page, 10)  # cap at 10
        parsed_bucket_id = int(bucket_id) if bucket_id else None
        if type == "Todo":
            results = await _run_sync(
                lambda: search.search_project_scoped_todos(
                    query,
                    bucket_id=parsed_bucket_id,
                    max_results=limit,
                )
            )
        else:
            results = await _run_sync(
                lambda: search.search_recordings_api(
                    query,
                    type=type,
                    bucket_id=parsed_bucket_id,
                    creator_id=int(creator_id) if creator_id else None,
                    file_type=file_type,
                    exclude_chat=exclude_chat,
                    page=page,
                    per_page=limit,
                )
            )
        if isinstance(results, list):
            results = [
                result for result in results
                if search._recording_matches_query(result, query)
                and search._recording_matches_type(result, type)
                and search._recording_matches_bucket(result, parsed_bucket_id)
            ][:10]
            if type == "Todo":
                results = compact_todos(results)
        return {
            "status": "success",
            "query": query,
            "recordings": results,
            "count": len(results) if isinstance(results, list) else 0,
        }
    except Exception as e:
        logger.error(f"Error in search_recordings: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {"error": "Execution error", "message": str(e)}


@mcp.tool()
async def get_comments(recording_id: str, project_id: str, page: int = 1) -> Dict[str, Any]:
    """Get comments for a Basecamp item.

    Args:
        recording_id: The item ID
        project_id: The project ID
        page: Page number for pagination (default: 1). Basecamp uses geared pagination:
              page 1 has 15 results, page 2 has 30, page 3 has 50, page 4+ has 100.
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()

    try:
        result = await _run_sync(client.get_comments, project_id, recording_id, page)
        comments = compact_comments(result["comments"])
        return {
            "status": "success",
            "comments": comments,
            "count": len(comments),
            "page": page,
            "total_count": result["total_count"],
            "next_page": result["next_page"]
        }
    except Exception as e:
        logger.error(f"Error getting comments: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def create_comment(recording_id: str, project_id: str, content: str) -> Dict[str, Any]:
    """Create a comment on a Basecamp item.

    Args:
        recording_id: The item ID
        project_id: The project ID
        content: The comment content in HTML format
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()

    try:
        comment = await _run_sync(client.create_comment, recording_id, project_id, content)
        return {
            "status": "success",
            "comment": compact_comment(comment),
            "message": "Comment created successfully"
        }
    except Exception as e:
        logger.error(f"Error creating comment: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again.",
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def get_campfire_lines(project_id: str, campfire_id: str) -> Dict[str, Any]:
    """Get recent messages from a Basecamp campfire (chat room).
    
    Args:
        project_id: The project ID
        campfire_id: The campfire/chat room ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        lines = await _run_sync(client.get_campfire_lines, project_id, campfire_id)
        return {
            "status": "success",
            "campfire_lines": lines,
            "count": len(lines)
        }
    except Exception as e:
        logger.error(f"Error getting campfire lines: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def get_message_board(project_id: str) -> Dict[str, Any]:
    """Get the message board for a project.

    Args:
        project_id: The project ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()

    try:
        message_board = await _run_sync(client.get_message_board, project_id)
        return {
            "status": "success",
            "message_board": message_board
        }
    except Exception as e:
        logger.error(f"Error getting message board: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def get_messages(project_id: str, message_board_id: Optional[str] = None) -> Dict[str, Any]:
    """Get all messages from a project's message board.

    Args:
        project_id: The project ID
        message_board_id: Optional message board ID. If not provided, will be auto-discovered from the project.
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()

    try:
        messages = await _run_sync(client.get_messages, project_id, message_board_id)
        return {
            "status": "success",
            "messages": messages,
            "count": len(messages)
        }
    except Exception as e:
        logger.error(f"Error getting messages: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def get_message(project_id: str, message_id: str) -> Dict[str, Any]:
    """Get a specific message by ID.

    Args:
        project_id: The project ID
        message_id: The message ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()

    try:
        message = await _run_sync(client.get_message, project_id, message_id)
        return {
            "status": "success",
            "message": message
        }
    except Exception as e:
        logger.error(f"Error getting message: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }


# Inbox Tools (Email Forwards)
@mcp.tool()
async def get_inbox(project_id: str) -> Dict[str, Any]:
    """Get the inbox for a project (for email forwards).

    Args:
        project_id: The project ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()

    try:
        inbox = await _run_sync(client.get_inbox, project_id)
        return {
            "status": "success",
            "inbox": inbox
        }
    except Exception as e:
        logger.error(f"Error getting inbox: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }


@mcp.tool()
async def get_forwards(project_id: str, inbox_id: Optional[str] = None) -> Dict[str, Any]:
    """Get all forwarded emails from a project's inbox.

    Args:
        project_id: The project ID
        inbox_id: Optional inbox ID. If not provided, will be auto-discovered from the project.
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()

    try:
        forwards = await _run_sync(client.get_forwards, project_id, inbox_id)
        return {
            "status": "success",
            "forwards": forwards,
            "count": len(forwards)
        }
    except Exception as e:
        logger.error(f"Error getting forwards: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }


@mcp.tool()
async def get_forward(project_id: str, forward_id: str) -> Dict[str, Any]:
    """Get a specific forwarded email by ID.

    Args:
        project_id: The project ID
        forward_id: The forward ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()

    try:
        forward = await _run_sync(client.get_forward, project_id, forward_id)
        return {
            "status": "success",
            "forward": forward
        }
    except Exception as e:
        logger.error(f"Error getting forward: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }


@mcp.tool()
async def get_inbox_replies(project_id: str, forward_id: str) -> Dict[str, Any]:
    """Get all replies to a forwarded email.

    Args:
        project_id: The project ID
        forward_id: The forward ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()

    try:
        replies = await _run_sync(client.get_inbox_replies, project_id, forward_id)
        return {
            "status": "success",
            "replies": replies,
            "count": len(replies)
        }
    except Exception as e:
        logger.error(f"Error getting inbox replies: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }


@mcp.tool()
async def get_inbox_reply(project_id: str, forward_id: str, reply_id: str) -> Dict[str, Any]:
    """Get a specific reply to a forwarded email.

    Args:
        project_id: The project ID
        forward_id: The forward ID
        reply_id: The reply ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()

    try:
        reply = await _run_sync(client.get_inbox_reply, project_id, forward_id, reply_id)
        return {
            "status": "success",
            "reply": reply
        }
    except Exception as e:
        logger.error(f"Error getting inbox reply: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }


@mcp.tool()
async def trash_forward(project_id: str, forward_id: str) -> Dict[str, Any]:
    """Move a forwarded email to trash.

    Args:
        project_id: The project ID
        forward_id: The forward ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()

    try:
        await _run_sync(client.trash_forward, project_id, forward_id)
        return {
            "status": "success",
            "message": "Forward trashed"
        }
    except Exception as e:
        logger.error(f"Error trashing forward: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }


@mcp.tool()
async def get_card_tables(project_id: str) -> Dict[str, Any]:
    """Get all card tables for a project.
    
    Args:
        project_id: The project ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        card_tables = await _run_sync(client.get_card_tables, project_id)
        return {
            "status": "success",
            "card_tables": card_tables,
            "count": len(card_tables)
        }
    except Exception as e:
        logger.error(f"Error getting card tables: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def get_card_table(project_id: str) -> Dict[str, Any]:
    """Get the card table details for a project.
    
    Args:
        project_id: The project ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        card_table = await _run_sync(client.get_card_table, project_id)
        card_table_details = await _run_sync(client.get_card_table_details, project_id, card_table['id'])
        return {
            "status": "success",
            "card_table": card_table_details
        }
    except Exception as e:
        logger.error(f"Error getting card table: {e}")
        error_msg = str(e)
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "status": "error",
            "message": f"Error getting card table: {error_msg}",
            "debug": error_msg
        }

@mcp.tool()
async def get_columns(project_id: str, card_table_id: str) -> Dict[str, Any]:
    """Get all columns in a card table.
    
    Args:
        project_id: The project ID
        card_table_id: The card table ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        columns = await _run_sync(client.get_columns, project_id, card_table_id)
        return {
            "status": "success",
            "columns": columns,
            "count": len(columns)
        }
    except Exception as e:
        logger.error(f"Error getting columns: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def get_cards(project_id: str, column_id: str) -> Dict[str, Any]:
    """Get all cards in a column.
    
    Args:
        project_id: The project ID
        column_id: The column ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        cards = await _run_sync(client.get_cards, project_id, column_id)
        return {
            "status": "success",
            "cards": cards,
            "count": len(cards)
        }
    except Exception as e:
        logger.error(f"Error getting cards: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def create_card(project_id: str, column_id: str, title: str, content: Optional[str] = None, due_on: Optional[str] = None, notify: bool = False) -> Dict[str, Any]:
    """Create a new card in a column.
    
    Args:
        project_id: The project ID
        column_id: The column ID
        title: The card title
        content: Optional card content/description
        due_on: Optional due date (ISO 8601 format)
        notify: Whether to notify assignees (default: false)
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        card = await _run_sync(client.create_card, project_id, column_id, title, content, due_on, notify)
        return {
            "status": "success",
            "card": card,
            "message": f"Card '{title}' created successfully"
        }
    except Exception as e:
        logger.error(f"Error creating card: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def get_column(project_id: str, column_id: str) -> Dict[str, Any]:
    """Get details for a specific column.
    
    Args:
        project_id: The project ID
        column_id: The column ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        column = await _run_sync(client.get_column, project_id, column_id)
        return {
            "status": "success",
            "column": column
        }
    except Exception as e:
        logger.error(f"Error getting column: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def create_column(project_id: str, card_table_id: str, title: str) -> Dict[str, Any]:
    """Create a new column in a card table.
    
    Args:
        project_id: The project ID
        card_table_id: The card table ID
        title: The column title
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        column = await _run_sync(client.create_column, project_id, card_table_id, title)
        return {
            "status": "success",
            "column": column,
            "message": f"Column '{title}' created successfully"
        }
    except Exception as e:
        logger.error(f"Error creating column: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def move_card(project_id: str, card_id: str, column_id: str) -> Dict[str, Any]:
    """Move a card to a new column.
    
    Args:
        project_id: The project ID
        card_id: The card ID
        column_id: The destination column ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        await _run_sync(client.move_card, project_id, card_id, column_id)
        return {
            "status": "success",
            "message": f"Card moved to column {column_id}"
        }
    except Exception as e:
        logger.error(f"Error moving card: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def complete_card(project_id: str, card_id: str) -> Dict[str, Any]:
    """Mark a card as complete.
    
    Args:
        project_id: The project ID
        card_id: The card ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        await _run_sync(client.complete_card, project_id, card_id)
        return {
            "status": "success",
            "message": "Card marked as complete"
        }
    except Exception as e:
        logger.error(f"Error completing card: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def get_card(project_id: str, card_id: str) -> Dict[str, Any]:
    """Get details for a specific card.
    
    Args:
        project_id: The project ID
        card_id: The card ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        card = await _run_sync(client.get_card, project_id, card_id)
        return {
            "status": "success",
            "card": card
        }
    except Exception as e:
        logger.error(f"Error getting card: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired", 
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def update_card(project_id: str, card_id: str, title: Optional[str] = None, content: Optional[str] = None, due_on: Optional[str] = None, assignee_ids: Optional[List[str]] = None) -> Dict[str, Any]:
    """Update a card.
    
    Args:
        project_id: The project ID
        card_id: The card ID
        title: The new card title
        content: The new card content/description
        due_on: Due date (ISO 8601 format)
        assignee_ids: Array of person IDs to assign to the card
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        card = await _run_sync(client.update_card, project_id, card_id, title, content, due_on, assignee_ids)
        return {
            "status": "success",
            "card": card,
            "message": "Card updated successfully"
        }
    except Exception as e:
        logger.error(f"Error updating card: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def get_daily_check_ins(project_id: str, page: Optional[int] = None) -> Dict[str, Any]:
    """Get project's daily checking questionnaire.
    
    Args:
        project_id: The project ID
        page: Page number paginated response
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        if page is not None and not isinstance(page, int):
            page = 1
        answers = await _run_sync(client.get_daily_check_ins, project_id, page=page or 1)
        return {
            "status": "success",
            "campfire_lines": answers,
            "count": len(answers)
        }
    except Exception as e:
        logger.error(f"Error getting daily check ins: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def get_question_answers(project_id: str, question_id: str, page: Optional[int] = None) -> Dict[str, Any]:
    """Get answers on daily check-in question.
    
    Args:
        project_id: The project ID
        question_id: The question ID
        page: Page number paginated response
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        if page is not None and not isinstance(page, int):
            page = 1
        answers = await _run_sync(client.get_question_answers, project_id, question_id, page=page or 1)
        return {
            "status": "success",
            "campfire_lines": answers,
            "count": len(answers)
        }
    except Exception as e:
        logger.error(f"Error getting question answers: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

# Column Management Tools
@mcp.tool()
async def update_column(project_id: str, column_id: str, title: str) -> Dict[str, Any]:
    """Update a column title.
    
    Args:
        project_id: The project ID
        column_id: The column ID
        title: The new column title
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        column = await _run_sync(client.update_column, project_id, column_id, title)
        return {
            "status": "success",
            "column": column,
            "message": "Column updated successfully"
        }
    except Exception as e:
        logger.error(f"Error updating column: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def move_column(project_id: str, card_table_id: str, column_id: str, position: int) -> Dict[str, Any]:
    """Move a column to a new position.
    
    Args:
        project_id: The project ID
        card_table_id: The card table ID
        column_id: The column ID
        position: The new 1-based position
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        await _run_sync(client.move_column, project_id, column_id, position, card_table_id)
        return {
            "status": "success",
            "message": f"Column moved to position {position}"
        }
    except Exception as e:
        logger.error(f"Error moving column: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def update_column_color(project_id: str, column_id: str, color: str) -> Dict[str, Any]:
    """Update a column color.
    
    Args:
        project_id: The project ID
        column_id: The column ID
        color: The hex color code (e.g., #FF0000)
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        column = await _run_sync(client.update_column_color, project_id, column_id, color)
        return {
            "status": "success",
            "column": column,
            "message": f"Column color updated to {color}"
        }
    except Exception as e:
        logger.error(f"Error updating column color: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def put_column_on_hold(project_id: str, column_id: str) -> Dict[str, Any]:
    """Put a column on hold (freeze work).
    
    Args:
        project_id: The project ID
        column_id: The column ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        await _run_sync(client.put_column_on_hold, project_id, column_id)
        return {
            "status": "success",
            "message": "Column put on hold"
        }
    except Exception as e:
        logger.error(f"Error putting column on hold: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def remove_column_hold(project_id: str, column_id: str) -> Dict[str, Any]:
    """Remove hold from a column (unfreeze work).
    
    Args:
        project_id: The project ID
        column_id: The column ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        await _run_sync(client.remove_column_hold, project_id, column_id)
        return {
            "status": "success",
            "message": "Column hold removed"
        }
    except Exception as e:
        logger.error(f"Error removing column hold: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def watch_column(project_id: str, column_id: str) -> Dict[str, Any]:
    """Subscribe to notifications for changes in a column.
    
    Args:
        project_id: The project ID
        column_id: The column ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        await _run_sync(client.watch_column, project_id, column_id)
        return {
            "status": "success",
            "message": "Column notifications enabled"
        }
    except Exception as e:
        logger.error(f"Error watching column: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def unwatch_column(project_id: str, column_id: str) -> Dict[str, Any]:
    """Unsubscribe from notifications for a column.
    
    Args:
        project_id: The project ID
        column_id: The column ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        await _run_sync(client.unwatch_column, project_id, column_id)
        return {
            "status": "success",
            "message": "Column notifications disabled"
        }
    except Exception as e:
        logger.error(f"Error unwatching column: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

# More Card Management Tools  
@mcp.tool()
async def uncomplete_card(project_id: str, card_id: str) -> Dict[str, Any]:
    """Mark a card as incomplete.
    
    Args:
        project_id: The project ID
        card_id: The card ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        await _run_sync(client.uncomplete_card, project_id, card_id)
        return {
            "status": "success",
            "message": "Card marked as incomplete"
        }
    except Exception as e:
        logger.error(f"Error uncompleting card: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

# Card Steps (Sub-tasks) Management
@mcp.tool()
async def get_card_steps(project_id: str, card_id: str) -> Dict[str, Any]:
    """Get all steps (sub-tasks) for a card.
    
    Args:
        project_id: The project ID
        card_id: The card ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        steps = await _run_sync(client.get_card_steps, project_id, card_id)
        return {
            "status": "success",
            "steps": steps,
            "count": len(steps)
        }
    except Exception as e:
        logger.error(f"Error getting card steps: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def create_card_step(project_id: str, card_id: str, title: str, due_on: Optional[str] = None, assignee_ids: Optional[List[str]] = None) -> Dict[str, Any]:
    """Create a new step (sub-task) for a card.
    
    Args:
        project_id: The project ID
        card_id: The card ID
        title: The step title
        due_on: Optional due date (ISO 8601 format)
        assignee_ids: Array of person IDs to assign to the step
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        step = await _run_sync(client.create_card_step, project_id, card_id, title, due_on, assignee_ids)
        return {
            "status": "success",
            "step": step,
            "message": f"Step '{title}' created successfully"
        }
    except Exception as e:
        logger.error(f"Error creating card step: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def get_card_step(project_id: str, step_id: str) -> Dict[str, Any]:
    """Get details for a specific card step.
    
    Args:
        project_id: The project ID
        step_id: The step ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        step = await _run_sync(client.get_card_step, project_id, step_id)
        return {
            "status": "success",
            "step": step
        }
    except Exception as e:
        logger.error(f"Error getting card step: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def update_card_step(project_id: str, step_id: str, title: Optional[str] = None, due_on: Optional[str] = None, assignee_ids: Optional[List[str]] = None) -> Dict[str, Any]:
    """Update a card step.
    
    Args:
        project_id: The project ID
        step_id: The step ID
        title: The step title
        due_on: Due date (ISO 8601 format)
        assignee_ids: Array of person IDs to assign to the step
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        step = await _run_sync(client.update_card_step, project_id, step_id, title, due_on, assignee_ids)
        return {
            "status": "success",
            "step": step,
            "message": f"Step updated successfully"
        }
    except Exception as e:
        logger.error(f"Error updating card step: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def delete_card_step(project_id: str, step_id: str) -> Dict[str, Any]:
    """Delete a card step.
    
    Args:
        project_id: The project ID
        step_id: The step ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        await _run_sync(client.delete_card_step, project_id, step_id)
        return {
            "status": "success",
            "message": "Step deleted successfully"
        }
    except Exception as e:
        logger.error(f"Error deleting card step: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def complete_card_step(project_id: str, step_id: str) -> Dict[str, Any]:
    """Mark a card step as complete.
    
    Args:
        project_id: The project ID
        step_id: The step ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        await _run_sync(client.complete_card_step, project_id, step_id)
        return {
            "status": "success",
            "message": "Step marked as complete"
        }
    except Exception as e:
        logger.error(f"Error completing card step: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def uncomplete_card_step(project_id: str, step_id: str) -> Dict[str, Any]:
    """Mark a card step as incomplete.
    
    Args:
        project_id: The project ID
        step_id: The step ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        await _run_sync(client.uncomplete_card_step, project_id, step_id)
        return {
            "status": "success",
            "message": "Step marked as incomplete"
        }
    except Exception as e:
        logger.error(f"Error uncompleting card step: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

# Attachments, Events, and Webhooks
@mcp.tool()
async def create_attachment(file_path: str, name: str, content_type: Optional[str] = None) -> Dict[str, Any]:
    """Upload a file as an attachment.
    
    Args:
        file_path: Local path to file
        name: Filename for Basecamp
        content_type: MIME type
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        result = await _run_sync(client.create_attachment, file_path, name, content_type or "application/octet-stream")
        return {
            "status": "success",
            "attachment": result
        }
    except Exception as e:
        logger.error(f"Error creating attachment: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def get_events(project_id: str, recording_id: str) -> Dict[str, Any]:
    """Get events for a recording.
    
    Args:
        project_id: Project ID
        recording_id: Recording ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        events = await _run_sync(client.get_events, project_id, recording_id)
        return {
            "status": "success",
            "events": events,
            "count": len(events)
        }
    except Exception as e:
        logger.error(f"Error getting events: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def get_webhooks(project_id: str) -> Dict[str, Any]:
    """List webhooks for a project.
    
    Args:
        project_id: Project ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        hooks = await _run_sync(client.get_webhooks, project_id)
        return {
            "status": "success",
            "webhooks": hooks,
            "count": len(hooks)
        }
    except Exception as e:
        logger.error(f"Error getting webhooks: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def create_webhook(project_id: str, payload_url: str, types: Optional[List[str]] = None) -> Dict[str, Any]:
    """Create a webhook.
    
    Args:
        project_id: Project ID
        payload_url: Payload URL
        types: Event types
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        hook = await _run_sync(client.create_webhook, project_id, payload_url, types)
        return {
            "status": "success",
            "webhook": hook
        }
    except Exception as e:
        logger.error(f"Error creating webhook: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def delete_webhook(project_id: str, webhook_id: str) -> Dict[str, Any]:
    """Delete a webhook.
    
    Args:
        project_id: Project ID
        webhook_id: Webhook ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        await _run_sync(client.delete_webhook, project_id, webhook_id)
        return {
            "status": "success",
            "message": "Webhook deleted"
        }
    except Exception as e:
        logger.error(f"Error deleting webhook: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

# Document Management
@mcp.tool()
async def get_documents(project_id: str, vault_id: str) -> Dict[str, Any]:
    """List documents in a vault.
    
    Args:
        project_id: Project ID
        vault_id: Vault ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        docs = await _run_sync(client.get_documents, project_id, vault_id)
        return {
            "status": "success",
            "documents": docs,
            "count": len(docs)
        }
    except Exception as e:
        logger.error(f"Error getting documents: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def get_document(project_id: str, document_id: str) -> Dict[str, Any]:
    """Get a single document.
    
    Args:
        project_id: Project ID
        document_id: Document ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        doc = await _run_sync(client.get_document, project_id, document_id)
        return {
            "status": "success",
            "document": doc
        }
    except Exception as e:
        logger.error(f"Error getting document: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def create_document(project_id: str, vault_id: str, title: str, content: str) -> Dict[str, Any]:
    """Create a document in a vault.
    
    Args:
        project_id: Project ID
        vault_id: Vault ID
        title: Document title
        content: Document HTML content
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        doc = await _run_sync(client.create_document, project_id, vault_id, title, content)
        return {
            "status": "success",
            "document": doc
        }
    except Exception as e:
        logger.error(f"Error creating document: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def update_document(project_id: str, document_id: str, title: Optional[str] = None, content: Optional[str] = None) -> Dict[str, Any]:
    """Update a document.
    
    Args:
        project_id: Project ID
        document_id: Document ID
        title: New title
        content: New HTML content
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        doc = await _run_sync(client.update_document, project_id, document_id, title, content)
        return {
            "status": "success",
            "document": doc
        }
    except Exception as e:
        logger.error(f"Error updating document: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def trash_document(project_id: str, document_id: str) -> Dict[str, Any]:
    """Move a document to trash.
    
    Args:
        project_id: Project ID
        document_id: Document ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        await _run_sync(client.trash_document, project_id, document_id)
        return {
            "status": "success",
            "message": "Document trashed"
        }
    except Exception as e:
        logger.error(f"Error trashing document: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

# Upload Management
@mcp.tool()
async def get_uploads(project_id: str, vault_id: Optional[str] = None) -> Dict[str, Any]:
    """List uploads in a project or vault.
    
    Args:
        project_id: Project ID
        vault_id: Optional vault ID to limit to specific vault
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        uploads = await _run_sync(client.get_uploads, project_id, vault_id)
        return {
            "status": "success",
            "uploads": uploads,
            "count": len(uploads)
        }
    except Exception as e:
        logger.error(f"Error getting uploads: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def get_upload(project_id: str, upload_id: str) -> Dict[str, Any]:
    """Get details for a specific upload.
    
    Args:
        project_id: Project ID
        upload_id: Upload ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()
    
    try:
        upload = await _run_sync(client.get_upload, project_id, upload_id)
        return {
            "status": "success",
            "upload": upload
        }
    except Exception as e:
        logger.error(f"Error getting upload: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {
                "error": "OAuth token expired",
                "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."
            }
        return {
            "error": "Execution error",
            "message": str(e)
        }

@mcp.tool()
async def get_todolist(project_id: str, todolist_id: str) -> Dict[str, Any]:
    """Get a specific todo list by ID.

    Args:
        project_id: The project ID
        todolist_id: The todo list ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()

    try:
        todolist = await _run_sync(client.get_todolist, project_id, todolist_id)
        return {"status": "success", "todolist": todolist}
    except Exception as e:
        logger.error(f"Error getting todolist {todolist_id}: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {"error": "OAuth token expired", "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."}
        return {"error": "Execution error", "message": str(e)}


@mcp.tool()
async def create_todolist(
    project_id: str,
    name: str,
    description: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a new todo list in a project.

    Args:
        project_id: The project ID
        name: Todo list name
        description: Optional HTML description
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()

    try:
        todolist = await _run_sync(
            lambda: client.create_todolist(project_id, name, description)
        )
        return {"status": "success", "todolist": todolist}
    except Exception as e:
        logger.error(f"Error creating todolist: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {"error": "OAuth token expired", "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."}
        return {"error": "Execution error", "message": str(e)}


@mcp.tool()
async def update_todolist(
    project_id: str,
    todolist_id: str,
    name: str,
    description: Optional[str] = None,
) -> Dict[str, Any]:
    """Update an existing todo list.

    The Basecamp API requires the name even when only updating the description.

    Args:
        project_id: The project ID
        todolist_id: The todo list ID
        name: Todo list name (required)
        description: Optional HTML description
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()

    try:
        todolist = await _run_sync(
            lambda: client.update_todolist(project_id, todolist_id, name, description)
        )
        return {"status": "success", "todolist": todolist}
    except Exception as e:
        logger.error(f"Error updating todolist {todolist_id}: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {"error": "OAuth token expired", "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."}
        return {"error": "Execution error", "message": str(e)}


@mcp.tool()
async def trash_todolist(project_id: str, todolist_id: str) -> Dict[str, Any]:
    """Move a todo list to the trash.

    Trashed lists can be recovered from the Basecamp web UI within 30 days.

    Args:
        project_id: The project ID
        todolist_id: The todo list ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()

    try:
        await _run_sync(client.trash_todolist, project_id, todolist_id)
        return {"status": "success", "message": f"Todolist {todolist_id} moved to trash"}
    except Exception as e:
        logger.error(f"Error trashing todolist {todolist_id}: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {"error": "OAuth token expired", "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."}
        return {"error": "Execution error", "message": str(e)}


@mcp.tool()
async def get_todolist_groups(project_id: str, todolist_id: str) -> Dict[str, Any]:
    """Get all groups in a todo list.

    Groups are named sections within a todo list (e.g. "Phase 1", "Backlog").

    Args:
        project_id: The project ID
        todolist_id: The todo list ID
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()

    try:
        groups = await _run_sync(client.get_todolist_groups, project_id, todolist_id)
        return {"status": "success", "groups": groups, "count": len(groups)}
    except Exception as e:
        logger.error(f"Error getting todolist groups: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {"error": "OAuth token expired", "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."}
        return {"error": "Execution error", "message": str(e)}


@mcp.tool()
async def create_todolist_group(
    project_id: str,
    todolist_id: str,
    name: str,
    color: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a new group inside a todo list.

    Groups act as named sections to organise todos within a list.

    Args:
        project_id: The project ID
        todolist_id: The todo list ID
        name: Group name
        color: Optional color – one of: white, red, orange, yellow, green,
               blue, aqua, purple, gray, pink, brown
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()

    try:
        group = await _run_sync(
            lambda: client.create_todolist_group(project_id, todolist_id, name, color)
        )
        return {"status": "success", "group": group}
    except Exception as e:
        logger.error(f"Error creating todolist group: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {"error": "OAuth token expired", "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."}
        return {"error": "Execution error", "message": str(e)}


@mcp.tool()
async def reposition_todolist_group(
    project_id: str, group_id: str, position: int
) -> Dict[str, Any]:
    """Reposition a todo list group to a new location within its list.

    Args:
        project_id: The project ID
        group_id: The group ID
        position: New 1-based position
    """
    client = _get_basecamp_client()
    if not client:
        return _get_auth_error_response()

    if position < 1:
        return {"error": "Invalid input", "message": "position must be >= 1"}

    try:
        await _run_sync(
            lambda: client.reposition_todolist_group(project_id, group_id, position)
        )
        return {"status": "success", "message": f"Group {group_id} repositioned to position {position}"}
    except Exception as e:
        logger.error(f"Error repositioning todolist group {group_id}: {e}")
        if "401" in str(e) and "expired" in str(e).lower():
            return {"error": "OAuth token expired", "message": "Your Basecamp OAuth token expired during the API call. Please re-authenticate by visiting http://localhost:8000 and completing the OAuth flow again."}
        return {"error": "Execution error", "message": str(e)}


# 🎉 COMPLETE FastMCP server with ALL tools migrated!

if __name__ == "__main__":
    logger.info("Starting Basecamp FastMCP server")
    # Run using official MCP stdio transport
    mcp.run(transport='stdio') 
