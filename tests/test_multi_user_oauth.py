import os
from urllib.parse import parse_qs, urlparse

import pytest

import basecamp_fastmcp
import basecamp_mcp_oauth
from basecamp_mcp_oauth import BasecampMcpOAuthProvider
from mcp.server.auth.provider import AuthorizationParams
from mcp.shared.auth import OAuthClientInformationFull
import oauth_store
from starlette.testclient import TestClient


@pytest.fixture(autouse=True)
def isolated_store(tmp_path, monkeypatch):
    monkeypatch.setattr(oauth_store, "DB_PATH", tmp_path / "oauth_state.sqlite3")
    oauth_store.clear_all()
    monkeypatch.setenv("BASECAMP_CLIENT_ID", "client-id")
    monkeypatch.setenv("BASECAMP_CLIENT_SECRET", "client-secret")
    monkeypatch.setenv("BASECAMP_REDIRECT_URI", "http://localhost:8051/basecamp/oauth/callback")
    monkeypatch.setenv("USER_AGENT", "Basecamp MCP Test (test@example.com)")
    monkeypatch.delenv("BASECAMP_ACCOUNT_ID", raising=False)
    monkeypatch.delenv("PUBLIC_BASE_URL", raising=False)
    monkeypatch.delenv("PUBLIC_MCP_URL", raising=False)
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    yield
    oauth_store.clear_all()


@pytest.fixture
def anyio_backend():
    return "asyncio"


def client_info() -> OAuthClientInformationFull:
    return OAuthClientInformationFull(
        client_id="mcp-client",
        redirect_uris=["http://127.0.0.1:9000/oauth/callback"],
        token_endpoint_auth_method="none",
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        scope="basecamp",
    )


def auth_params() -> AuthorizationParams:
    return AuthorizationParams(
        state="client-state",
        scopes=["basecamp"],
        code_challenge="challenge",
        redirect_uri="http://127.0.0.1:9000/oauth/callback",
        redirect_uri_provided_explicitly=True,
        resource="http://localhost:8051/mcp",
    )


def test_health_route_reports_ok():
    client = TestClient(basecamp_fastmcp.mcp.streamable_http_app())

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def service_headers():
    return {"Authorization": "Bearer permanent-service-token"}


def save_service_user(user_id="service-user"):
    oauth_store.save_basecamp_user(
        user_id=user_id,
        identity={"identity": {"id": user_id, "email_address": "service@example.com"}},
        accounts=[{"id": 111, "name": "First", "product": "bc3"}],
        active_account_id="111",
        access_token="basecamp-access",
        refresh_token="basecamp-refresh",
        expires_at=oauth_store.now() + 3600,
    )


def test_service_auth_status_route_requires_service_token(monkeypatch):
    monkeypatch.setenv("BASECAMP_MCP_AUTH_TOKEN", "permanent-service-token")
    monkeypatch.setenv("BASECAMP_MCP_AUTH_USER_ID", "service-user")
    client = TestClient(basecamp_fastmcp.mcp.streamable_http_app())

    response = client.get("/basecamp/api/auth/status")

    assert response.status_code == 401


def test_service_auth_status_route_reports_bound_basecamp_user(monkeypatch):
    monkeypatch.setenv("BASECAMP_MCP_AUTH_TOKEN", "permanent-service-token")
    monkeypatch.setenv("BASECAMP_MCP_AUTH_USER_ID", "service-user")
    save_service_user()
    client = TestClient(basecamp_fastmcp.mcp.streamable_http_app())

    response = client.get("/basecamp/api/auth/status", headers=service_headers())

    assert response.status_code == 200
    body = response.json()
    assert body["authenticated"] is True
    assert body["service_user_id"] == "service-user"
    assert body["active_account_id"] == "111"


def test_service_auth_url_route_returns_basecamp_authorization_url(monkeypatch):
    monkeypatch.setenv("BASECAMP_MCP_AUTH_TOKEN", "permanent-service-token")
    monkeypatch.setenv("BASECAMP_MCP_AUTH_USER_ID", "service-user")
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://ai.services.key.study/mcp/bc")
    monkeypatch.delenv("BASECAMP_REDIRECT_URI", raising=False)
    client = TestClient(basecamp_fastmcp.mcp.streamable_http_app())

    response = client.get("/basecamp/api/auth/url", headers=service_headers())

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "success"
    assert body["service_user_id"] == "service-user"
    assert body["callback_url"] == "https://ai.services.key.study/mcp/bc/basecamp/oauth/callback"
    assert "https://launchpad.37signals.com/authorization/new?" in body["authorization_url"]
    assert "state=" in body["authorization_url"]


def test_service_auth_url_route_can_be_account_bound(monkeypatch):
    monkeypatch.setenv("BASECAMP_MCP_AUTH_TOKEN", "permanent-service-token")
    monkeypatch.delenv("BASECAMP_MCP_AUTH_USER_ID", raising=False)
    monkeypatch.setenv("BASECAMP_MCP_AUTH_ACCOUNT_ID", "111")
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://ai.services.key.study/mcp/bc")
    client = TestClient(basecamp_fastmcp.mcp.streamable_http_app())

    response = client.get("/basecamp/api/auth/url", headers=service_headers())

    assert response.status_code == 200
    body = response.json()
    assert body["service_user_id"] is None
    assert body["service_account_id"] == "111"
    assert "state=" in body["authorization_url"]


def test_account_bound_auth_url_does_not_pin_resolved_user(monkeypatch):
    monkeypatch.setenv("BASECAMP_MCP_AUTH_TOKEN", "permanent-service-token")
    monkeypatch.delenv("BASECAMP_MCP_AUTH_USER_ID", raising=False)
    monkeypatch.setenv("BASECAMP_MCP_AUTH_ACCOUNT_ID", "111")
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://ai.services.key.study/mcp/bc")
    save_service_user(user_id="previous-account-user")
    client = TestClient(basecamp_fastmcp.mcp.streamable_http_app())

    response = client.get("/basecamp/api/auth/url", headers=service_headers())

    assert response.status_code == 200
    body = response.json()
    state = parse_qs(urlparse(body["authorization_url"]).query)["state"][0]
    pending = oauth_store.pop_state(state)
    assert pending["auth_params"] == {"mode": "service_reconnect", "account_id": "111"}
    assert body["service_user_id"] is None
    assert body["resolved_user_id"] == "previous-account-user"


@pytest.mark.anyio
async def test_provider_accepts_configured_service_auth_token_for_latest_account_user(monkeypatch):
    monkeypatch.setenv("BASECAMP_MCP_AUTH_TOKEN", "permanent-service-token")
    monkeypatch.delenv("BASECAMP_MCP_AUTH_USER_ID", raising=False)
    monkeypatch.setenv("BASECAMP_MCP_AUTH_ACCOUNT_ID", "111")
    save_service_user(user_id="account-service-user")

    loaded_access = await BasecampMcpOAuthProvider().load_access_token("permanent-service-token")

    assert loaded_access is not None
    assert loaded_access.client_id == "basecamp-mcp-service"
    assert loaded_access.user_id == "account-service-user"
    assert loaded_access.scopes == ["basecamp"]


def test_service_webhook_registration_url_route_returns_direct_basecamp_api_details(monkeypatch):
    monkeypatch.setenv("BASECAMP_MCP_AUTH_TOKEN", "permanent-service-token")
    monkeypatch.setenv("BASECAMP_MCP_AUTH_USER_ID", "service-user")
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://ai.services.key.study/mcp/bc")
    save_service_user()
    client = TestClient(basecamp_fastmcp.mcp.streamable_http_app())

    response = client.get(
        "/basecamp/api/webhooks/register-url?project_id=40016505",
        headers=service_headers(),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["url"] == "https://3.basecampapi.com/111/buckets/40016505/webhooks.json"
    assert body["mcp_api_url"] == "https://ai.services.key.study/mcp/bc/basecamp/api/webhooks"
    assert body["headers"]["Authorization"] == "Bearer <Basecamp OAuth access token>"


def test_service_create_webhook_route_registers_webhook(monkeypatch):
    class FakeBasecampClient:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def create_webhook(self, project_id, payload_url, types=None):
            return {
                "id": 123,
                "project_id": project_id,
                "payload_url": payload_url,
                "types": types,
            }

    monkeypatch.setenv("BASECAMP_MCP_AUTH_TOKEN", "permanent-service-token")
    monkeypatch.setenv("BASECAMP_MCP_AUTH_USER_ID", "service-user")
    monkeypatch.setattr(basecamp_fastmcp, "BasecampClient", FakeBasecampClient)
    save_service_user()
    client = TestClient(basecamp_fastmcp.mcp.streamable_http_app())

    response = client.post(
        "/basecamp/api/webhooks",
        headers=service_headers(),
        json={
            "project_id": "40016505",
            "payload_url": "https://example.com/basecamp/webhook",
            "types": ["Todo", "Comment"],
        },
    )

    assert response.status_code == 201
    assert response.json()["webhook"] == {
        "id": 123,
        "project_id": "40016505",
        "payload_url": "https://example.com/basecamp/webhook",
        "types": ["Todo", "Comment"],
    }


class FakeBasecampOAuth:
    def __init__(self, *args, **kwargs):
        pass

    def get_authorization_url(self, state=None, scope=None):
        return f"https://launchpad.37signals.com/authorization/new?state={state}"

    def exchange_code_for_token(self, code):
        return {
            "access_token": f"basecamp-access-{code}",
            "refresh_token": f"basecamp-refresh-{code}",
            "expires_in": 3600,
        }

    def get_identity(self, access_token):
        return {
            "identity": {"id": 123, "email_address": "person@example.com"},
            "accounts": [
                {"id": 111, "name": "First", "product": "bc3"},
                {"id": 222, "name": "Second", "product": "bc3"},
            ],
        }


class CapturingBasecampOAuth(FakeBasecampOAuth):
    instances = []

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        self.__class__.instances.append(self)


@pytest.mark.anyio
async def test_provider_completes_basecamp_callback_and_issues_mcp_tokens(monkeypatch):
    monkeypatch.setattr(basecamp_mcp_oauth, "BasecampOAuth", FakeBasecampOAuth)
    provider = BasecampMcpOAuthProvider()
    await provider.register_client(client_info())

    redirect_to_basecamp = await provider.authorize(client_info(), auth_params())
    state = redirect_to_basecamp.split("state=", 1)[1]

    client_redirect = await provider.complete_basecamp_authorization(state, "abc")
    assert client_redirect.startswith("http://127.0.0.1:9000/oauth/callback?")
    assert "state=client-state" in client_redirect

    code = client_redirect.split("code=", 1)[1].split("&", 1)[0]
    auth_code = await provider.load_authorization_code(client_info(), code)
    assert auth_code.user_id == "123"
    assert auth_code.client_id == "mcp-client"

    token = await provider.exchange_authorization_code(client_info(), auth_code)
    assert token.access_token
    assert token.refresh_token

    loaded_access = await provider.load_access_token(token.access_token)
    assert loaded_access.user_id == "123"
    assert loaded_access.scopes == ["basecamp"]


@pytest.mark.anyio
async def test_provider_accepts_configured_service_auth_token(monkeypatch):
    monkeypatch.setenv("BASECAMP_MCP_AUTH_TOKEN", "permanent-service-token")
    monkeypatch.setenv("BASECAMP_MCP_AUTH_USER_ID", "service-user")
    monkeypatch.setenv("PUBLIC_MCP_URL", "https://ai.services.key.study/mcp/bc")

    loaded_access = await BasecampMcpOAuthProvider().load_access_token("permanent-service-token")

    assert loaded_access is not None
    assert loaded_access.client_id == "basecamp-mcp-service"
    assert loaded_access.user_id == "service-user"
    assert loaded_access.scopes == ["basecamp"]
    assert loaded_access.expires_at is None
    assert loaded_access.resource == "https://ai.services.key.study/mcp/bc"


@pytest.mark.anyio
async def test_provider_rejects_invalid_service_auth_token(monkeypatch):
    monkeypatch.setenv("BASECAMP_MCP_AUTH_TOKEN", "permanent-service-token")
    monkeypatch.setenv("BASECAMP_MCP_AUTH_USER_ID", "service-user")

    assert await BasecampMcpOAuthProvider().load_access_token("wrong-token") is None


@pytest.mark.anyio
async def test_provider_requires_user_binding_for_service_auth_token(monkeypatch):
    monkeypatch.setenv("BASECAMP_MCP_AUTH_TOKEN", "permanent-service-token")
    monkeypatch.delenv("BASECAMP_MCP_AUTH_USER_ID", raising=False)

    assert await BasecampMcpOAuthProvider().load_access_token("permanent-service-token") is None


def test_auth_settings_use_path_based_public_mcp_url(monkeypatch):
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://ai.services.key.study/mcp/bc")
    monkeypatch.setenv("PUBLIC_MCP_URL", "https://ai.services.key.study/mcp/bc")

    settings = basecamp_fastmcp._auth_settings()

    assert str(settings.issuer_url).rstrip("/") == "https://ai.services.key.study/mcp/bc"
    assert str(settings.resource_server_url).rstrip("/") == "https://ai.services.key.study/mcp/bc"


def test_auth_settings_append_mcp_for_domain_only_public_base_url(monkeypatch):
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://basecamp-mcp.example.com")
    monkeypatch.delenv("PUBLIC_MCP_URL", raising=False)

    settings = basecamp_fastmcp._auth_settings()

    assert str(settings.issuer_url).rstrip("/") == "https://basecamp-mcp.example.com"
    assert str(settings.resource_server_url).rstrip("/") == "https://basecamp-mcp.example.com/mcp"


def test_basecamp_redirect_uri_defaults_to_path_based_callback(monkeypatch):
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://ai.services.key.study/mcp/bc")
    monkeypatch.delenv("BASECAMP_REDIRECT_URI", raising=False)

    assert (
        basecamp_mcp_oauth.basecamp_redirect_uri()
        == "https://ai.services.key.study/mcp/bc/basecamp/oauth/callback"
    )


@pytest.mark.anyio
async def test_provider_uses_path_based_basecamp_redirect_uri(monkeypatch):
    CapturingBasecampOAuth.instances = []
    monkeypatch.setattr(basecamp_mcp_oauth, "BasecampOAuth", CapturingBasecampOAuth)
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://ai.services.key.study/mcp/bc")
    monkeypatch.delenv("BASECAMP_REDIRECT_URI", raising=False)

    provider = BasecampMcpOAuthProvider()
    await provider.register_client(client_info())
    await provider.authorize(client_info(), auth_params())

    assert CapturingBasecampOAuth.instances
    assert (
        CapturingBasecampOAuth.instances[-1].kwargs["redirect_uri"]
        == "https://ai.services.key.study/mcp/bc/basecamp/oauth/callback"
    )


def test_store_keeps_mcp_access_tokens_bound_to_separate_users():
    oauth_store.save_access_token(
        "token-a",
        {
            "client_id": "client",
            "user_id": "user-a",
            "scopes": ["basecamp"],
            "expires_at": oauth_store.now() + 300,
        },
    )
    oauth_store.save_access_token(
        "token-b",
        {
            "client_id": "client",
            "user_id": "user-b",
            "scopes": ["basecamp"],
            "expires_at": oauth_store.now() + 300,
        },
    )

    assert oauth_store.find_user_id_for_access_token("token-a") == "user-a"
    assert oauth_store.find_user_id_for_access_token("token-b") == "user-b"


def test_choose_active_account_respects_configured_account(monkeypatch):
    identity = {
        "accounts": [
            {"id": 111, "name": "First", "product": "bc3"},
            {"id": 222, "name": "Second", "product": "bc3"},
        ]
    }

    assert basecamp_mcp_oauth.choose_active_account(identity) == "111"
    monkeypatch.setenv("BASECAMP_ACCOUNT_ID", "222")
    assert basecamp_mcp_oauth.choose_active_account(identity) == "222"
    monkeypatch.setenv("BASECAMP_ACCOUNT_ID", "333")
    assert basecamp_mcp_oauth.choose_active_account(identity) is None
