import os

import pytest

import basecamp_fastmcp
import basecamp_mcp_oauth
from basecamp_mcp_oauth import BasecampMcpOAuthProvider
from mcp.server.auth.provider import AuthorizationParams
from mcp.shared.auth import OAuthClientInformationFull
import oauth_store


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
