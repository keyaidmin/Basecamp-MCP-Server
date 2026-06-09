from unittest.mock import Mock, patch

import pytest

import basecamp_fastmcp
from basecamp_client import BasecampClient
from search_utils import BasecampSearch


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


def test_get_recordings_requests_latest_updated_todos_first():
    client = make_client()
    first_page = [{"id": 1, "type": "Todo", "updated_at": "2026-05-12T12:00:00Z"}]
    next_link = '<https://3.basecampapi.com/12345/projects/recordings.json?page=2>; rel="next"'

    with patch.object(
        client,
        "get",
        side_effect=[
            make_response(200, first_page, next_link),
            make_response(200, [{"id": 2, "type": "Todo", "updated_at": "2026-05-11T12:00:00Z"}]),
        ],
    ) as mock_get:
        recordings = client.get_recordings("Todo", bucket=999, sort="updated_at", direction="desc")

    assert [recording["id"] for recording in recordings] == [1, 2]
    assert mock_get.call_args_list[0].args == ("projects/recordings.json",)
    assert mock_get.call_args_list[0].kwargs == {
        "params": {
            "type": "Todo",
            "status": "active",
            "sort": "updated_at",
            "direction": "desc",
            "page": 1,
            "bucket": 999,
        }
    }


def test_get_project_todos_uses_project_recordings_limit():
    client = make_client()

    with patch.object(
        client,
        "get_recordings",
        return_value=[{"id": index, "type": "Todo"} for index in range(1, 20)],
    ) as mock_get_recordings:
        todos = client.get_project_todos("999", limit=16)

    assert [todo["id"] for todo in todos] == list(range(1, 17))
    mock_get_recordings.assert_called_once_with(
        "Todo",
        bucket="999",
        status="active",
        sort="updated_at",
        direction="desc",
        max_pages=2,
    )


def test_get_all_comments_paginates_until_done():
    client = make_client()

    with patch.object(
        client,
        "get_comments",
        side_effect=[
            {"comments": [{"id": 1}], "total_count": 2, "next_page": 2},
            {"comments": [{"id": 2}], "total_count": 2, "next_page": None},
        ],
    ) as mock_get_comments:
        result = client.get_all_comments("999", "123")

    assert result == {
        "comments": [{"id": 1}, {"id": 2}],
        "total_count": 2,
        "fetched_count": 2,
        "has_more": False,
    }
    assert mock_get_comments.call_args_list[0].args == ("999", "123", 1)
    assert mock_get_comments.call_args_list[1].args == ("999", "123", 2)


def test_search_todos_prioritizes_latest_updated_recordings_before_search_api():
    class FakeClient:
        def get_recordings(self, recording_type, **kwargs):
            assert recording_type == "Todo"
            assert kwargs["sort"] == "updated_at"
            assert kwargs["direction"] == "desc"
            return [
                {"id": 1, "type": "Todo", "content": "Latest matching task", "updated_at": "2026-05-12T12:00:00Z"},
                {"id": 2, "type": "Todo", "content": "Older matching task", "updated_at": "2026-05-11T12:00:00Z"},
                {"id": 3, "type": "Todo", "content": "Unrelated", "updated_at": "2026-05-13T12:00:00Z"},
            ]

        def search_recordings(self, **kwargs):
            assert kwargs["type"] in ("Todo", "Comment")
            if kwargs["type"] == "Todo":
                return [{"id": 4, "type": "Todo", "title": "Fallback matching task"}]
            return [{"id": 5, "type": "Comment", "title": "matching comment"}]

    results = BasecampSearch(client=FakeClient()).search_recordings_api_todos_and_comments(
        "matching",
        max_results=4,
    )

    assert [(result["type"], result["id"]) for result in results] == [
        ("Todo", 1),
        ("Todo", 2),
        ("Todo", 4),
        ("Comment", 5),
    ]


def test_project_scoped_search_filters_unrelated_official_search_results():
    class FakeClient:
        account_id = "12345"

        def get_project(self, project_id):
            assert project_id == "999"
            return {"id": "999", "name": "Automation Project"}

        def get_project_todos(self, project_id, limit=100):
            assert project_id == "999"
            return [
                {
                    "id": 10,
                    "type": "Todo",
                    "content": "Automation task",
                    "description": "Build offboarding automation",
                    "updated_at": "2026-05-20T12:00:00Z",
                },
                {
                    "id": 11,
                    "type": "Todo",
                    "content": "Lunch order",
                    "description": "Unrelated",
                    "updated_at": "2026-05-21T12:00:00Z",
                },
            ]

        def get_recordings(self, recording_type, **kwargs):
            assert recording_type == "Todo"
            return [{"id": 12, "type": "Todo", "content": "Unrelated recent task"}]

        def search_recordings(self, **kwargs):
            return [{"id": 13, "type": "Todo", "content": "Unrelated API result"}]

    results = BasecampSearch(client=FakeClient()).search_recordings_api_todos_and_comments(
        "automation",
        bucket_id="999",
        max_results=10,
    )

    assert [(result["type"], result["id"]) for result in results] == [("Todo", 10)]


def test_global_project_scoped_search_scans_projects_and_sorts_matches():
    class FakeClient:
        account_id = "12345"

        def get_projects(self):
            return [
                {
                    "id": "1",
                    "name": "Older Project",
                    "updated_at": "2026-05-20T12:00:00Z",
                    "dock": [{"name": "todoset", "enabled": True}],
                },
                {
                    "id": "2",
                    "name": "Newer Project",
                    "updated_at": "2026-05-21T12:00:00Z",
                    "dock": [{"name": "todoset", "enabled": True}],
                },
            ]

        def get_project_todos(self, project_id, limit=100):
            if project_id == "1":
                return [
                    {
                        "id": 1,
                        "type": "Todo",
                        "content": "Automation roadmap",
                        "updated_at": "2026-05-20T12:00:00Z",
                    }
                ]
            return [
                {
                    "id": 2,
                    "type": "Todo",
                    "content": "AI automation briefing",
                    "updated_at": "2026-05-22T12:00:00Z",
                },
                {
                    "id": 3,
                    "type": "Todo",
                    "content": "Unrelated",
                    "updated_at": "2026-05-23T12:00:00Z",
                },
            ]

    results = BasecampSearch(client=FakeClient()).search_project_scoped_todos(
        "automation",
        max_results=10,
    )

    assert [(result["type"], result["id"]) for result in results] == [
        ("Todo", 2),
        ("Todo", 1),
    ]


@pytest.mark.anyio
async def test_global_search_returns_latest_updated_todos_first(monkeypatch):
    class FakeClient:
        pass

    def fake_search(_self, query, bucket_id=None, max_results=10):
        assert query == "matching"
        assert bucket_id is None
        assert max_results == 10
        return [
            {"id": 1, "type": "Todo", "content": "Latest matching task", "updated_at": "2026-05-12T12:00:00Z"},
            {"id": 2, "type": "Todo", "content": "Older matching task", "updated_at": "2026-05-11T12:00:00Z"},
        ]

    monkeypatch.setattr(basecamp_fastmcp, "_get_basecamp_client", lambda: FakeClient())
    monkeypatch.setattr(BasecampSearch, "search_recordings_api_todos_and_comments", fake_search)

    result = await basecamp_fastmcp.global_search("matching")

    assert result["status"] == "success"
    assert [recording["id"] for recording in result["recordings"]] == [1, 2]
    assert result["count"] == 2
