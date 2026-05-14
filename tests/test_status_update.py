from datetime import datetime, timezone

import pytest

import basecamp_fastmcp
from basecamp_context import load_or_create_summary
from status_update import select_recent_comments


def test_select_recent_comments_prefers_week_window():
    comments = [
        {"id": 1, "content": "old", "created_at": "2026-05-01T10:00:00Z"},
        {"id": 2, "content": "recent", "created_at": "2026-05-13T10:00:00Z"},
    ]

    selected = select_recent_comments(
        comments,
        days=7,
        fallback_count=5,
        now=datetime(2026, 5, 14, tzinfo=timezone.utc),
    )

    assert [comment["id"] for comment in selected] == [2]


def test_select_recent_comments_falls_back_to_latest_comments():
    comments = [
        {"id": 1, "content": "oldest", "created_at": "2026-04-01T10:00:00Z"},
        {"id": 2, "content": "newest", "created_at": "2026-04-02T10:00:00Z"},
    ]

    selected = select_recent_comments(
        comments,
        days=7,
        fallback_count=1,
        now=datetime(2026, 5, 14, tzinfo=timezone.utc),
    )

    assert [comment["id"] for comment in selected] == [2]


def test_context_summary_cache_reuses_same_comment_signature(tmp_path):
    db_path = tmp_path / "context.sqlite3"
    comments = [
        {
            "id": 1,
            "content": "First comment",
            "created_at": "2026-05-14T09:00:00Z",
            "creator": {"name": "Yuriy"},
        }
    ]

    created = load_or_create_summary("10", "20", comments, db_path=str(db_path))
    cached = load_or_create_summary("10", "20", comments, db_path=str(db_path))

    assert created["cached"] is False
    assert cached["cached"] is True
    assert cached["summary"] == created["summary"]
    assert cached["cache_created_at"] > 0
    assert cached["cache_updated_at"] > 0


@pytest.mark.anyio
async def test_get_project_status_update_returns_compact_updates(monkeypatch):
    class FakeClient:
        def get_project_todos(self, project_id, status, limit):
            assert project_id == "10"
            assert status == "active"
            assert limit == 2
            return [
                {
                    "id": 20,
                    "type": "Todo",
                    "content": "<b>Recent task</b>",
                    "updated_at": "2026-05-14T11:00:00Z",
                }
            ]

        def get_all_comments(self, project_id, recording_id):
            assert project_id == "10"
            assert recording_id == "20"
            return {
                "comments": [
                    {
                        "id": 30,
                        "content": "<p>Latest comment</p>",
                        "created_at": "2026-05-14T10:00:00Z",
                        "creator": {"id": 1, "name": "Yuriy", "avatar_url": "drop"},
                    }
                ],
                "total_count": 1,
                "fetched_count": 1,
                "has_more": False,
            }

    def fake_summary(project_id, todo_id, comments):
        assert project_id == "10"
        assert todo_id == "20"
        assert comments[0]["content"] == "Latest comment"
        return {
            "summary": "Latest comment context",
            "cached": False,
            "latest_comment_at": "2026-05-14T10:00:00Z",
        }

    monkeypatch.setattr(basecamp_fastmcp, "_get_basecamp_client", lambda: FakeClient())
    monkeypatch.setattr(basecamp_fastmcp, "load_or_create_summary", fake_summary)

    result = await basecamp_fastmcp.get_project_status_update("10", todo_limit=2)

    assert result["status"] == "success"
    assert result["project_id"] == "10"
    assert result["todo_count"] == 1
    assert result["updates"] == [
        {
            "todo": {
                "id": 20,
                "type": "Todo",
                "content": "Recent task",
                "updated_at": "2026-05-14T11:00:00Z",
            },
            "comment_context": {
                "summary": "Latest comment context",
                "cached": False,
                "latest_comment_at": "2026-05-14T10:00:00Z",
                "total_fetched_comments": 1,
                "total_comments": 1,
                "has_more_comments": False,
                "returned_recent_comments": 1,
            },
            "recent_comments": [
                {
                    "id": 30,
                    "content": "Latest comment",
                    "created_at": "2026-05-14T10:00:00Z",
                    "creator": {"id": 1, "name": "Yuriy"},
                }
            ],
        }
    ]


@pytest.mark.anyio
async def test_prepare_todo_context_returns_cached_summary_metadata(monkeypatch):
    class FakeClient:
        def get_todo(self, project_id, todo_id):
            assert project_id == "10"
            assert todo_id == "20"
            return {
                "id": 20,
                "type": "Todo",
                "content": "<b>Task summary target</b>",
                "updated_at": "2026-05-14T11:00:00Z",
            }

        def get_all_comments(self, project_id, recording_id, max_pages):
            assert project_id == "10"
            assert recording_id == "20"
            assert max_pages == 6
            return {
                "comments": [
                    {
                        "id": 30,
                        "content": "<p>Important task context</p>",
                        "created_at": "2026-05-14T10:00:00Z",
                        "creator": {"id": 1, "name": "Yuriy"},
                    }
                ],
                "total_count": 1,
                "has_more": False,
            }

    def fake_summary(
        project_id,
        todo_id,
        comments,
        force_refresh=False,
        total_comments=None,
        fetched_comments=None,
        has_more_comments=False,
    ):
        assert project_id == "10"
        assert todo_id == "20"
        assert force_refresh is True
        assert comments[0]["content"] == "Important task context"
        assert total_comments == 1
        assert fetched_comments == 1
        assert has_more_comments is False
        return {
            "summary": "Important task context",
            "cached": False,
            "cache_created_at": 111,
            "cache_updated_at": 222,
            "latest_comment_at": "2026-05-14T10:00:00Z",
            "total_comments": 1,
            "fetched_comments": 1,
            "has_more_comments": False,
        }

    monkeypatch.setattr(basecamp_fastmcp, "_get_basecamp_client", lambda: FakeClient())
    monkeypatch.setattr(basecamp_fastmcp, "load_or_create_summary", fake_summary)

    result = await basecamp_fastmcp.prepare_todo_context(
        "10",
        "20",
        force_refresh=True,
        max_comment_pages=6,
    )

    assert result == {
        "status": "success",
        "project_id": "10",
        "todo_id": "20",
        "todo": {
            "id": 20,
            "type": "Todo",
            "content": "Task summary target",
            "updated_at": "2026-05-14T11:00:00Z",
        },
        "context": {
            "summary": "Important task context",
            "cached": False,
            "cache_created_at": 111,
            "cache_updated_at": 222,
            "latest_comment_at": "2026-05-14T10:00:00Z",
            "total_comments": 1,
            "total_fetched_comments": 1,
            "has_more_comments": False,
        },
    }
