from unittest.mock import Mock, patch

import pytest

import basecamp_fastmcp
from basecamp_client import BasecampClient


def make_client():
    return BasecampClient(
        access_token="test-token",
        account_id="12345",
        user_agent="Basecamp MCP Test (test@example.com)",
        auth_mode="oauth",
    )


def make_response(status_code, payload, link=""):
    response = Mock()
    response.status_code = status_code
    response.json.return_value = payload
    response.headers = {"Link": link} if link else {}
    response.text = "response text"
    return response


def test_get_projects_returns_all_paginated_projects():
    client = make_client()
    first_page = [{"id": index, "name": f"Project {index}"} for index in range(1, 16)]
    second_page = [{"id": index, "name": f"Project {index}"} for index in range(16, 19)]
    next_link = '<https://3.basecampapi.com/12345/projects.json?page=2>; rel="next"'

    with patch.object(
        client,
        "get",
        side_effect=[
            make_response(200, first_page, next_link),
            make_response(200, second_page),
        ],
    ) as mock_get:
        projects = client.get_projects()

    assert len(projects) == 18
    assert projects[0]["id"] == 1
    assert projects[-1]["id"] == 18
    assert mock_get.call_args_list[0].args == ("projects.json",)
    assert mock_get.call_args_list[0].kwargs == {"params": {"page": 1}}
    assert mock_get.call_args_list[1].kwargs == {"params": {"page": 2}}


def test_get_projects_stops_when_page_is_empty_even_with_next_link():
    client = make_client()
    next_link = '<https://3.basecampapi.com/12345/projects.json?page=2>; rel="next"'

    with patch.object(
        client,
        "get",
        side_effect=[
            make_response(200, [{"id": 1, "name": "Project 1"}], next_link),
            make_response(200, [], next_link),
        ],
    ) as mock_get:
        projects = client.get_projects()

    assert projects == [{"id": 1, "name": "Project 1"}]
    assert mock_get.call_count == 2


def test_get_projects_raises_on_non_successful_page():
    client = make_client()

    with patch.object(client, "get", return_value=make_response(500, {"error": "boom"})):
        with pytest.raises(Exception, match="Failed to get projects: 500 - response text"):
            client.get_projects()


@pytest.mark.anyio
async def test_get_projects_tool_returns_paginated_client_count(monkeypatch):
    class FakeClient:
        def get_projects(self):
            return [{"id": index, "name": f"Project {index}"} for index in range(1, 19)]

    monkeypatch.setattr(basecamp_fastmcp, "_get_basecamp_client", lambda: FakeClient())

    result = await basecamp_fastmcp.get_projects()

    assert result["status"] == "success"
    assert result["count"] == 18
    assert result["projects"][-1]["name"] == "Project 18"
