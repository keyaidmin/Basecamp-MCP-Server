import pytest

import basecamp_fastmcp
from todo_context import compact_todo, compact_todos


def test_compact_todo_strips_html_and_keeps_usable_fields():
    todo = {
        "id": 123,
        "type": "Todo",
        "content": "<strong>Review OAuth</strong><br>Ship fix",
        "description": "<p>Long <em>HTML</em> body&nbsp;with details.</p>",
        "completed": False,
        "updated_at": "2026-05-14T09:00:00Z",
        "bucket": {"id": 10, "name": "Basecamp MCP", "type": "Project", "unused": "drop"},
        "parent": {"id": 20, "title": "OAuth tasks", "type": "Todolist"},
        "creator": {"id": 30, "name": "Yuriy", "avatar_url": "drop"},
        "assignees": [{"id": 31, "name": "Dev", "admin": True}],
        "comments_count": 5,
    }

    compacted = compact_todo(todo)

    assert compacted == {
        "id": 123,
        "type": "Todo",
        "content": "Review OAuth\nShip fix",
        "description": "Long HTML body with details.",
        "completed": False,
        "updated_at": "2026-05-14T09:00:00Z",
        "bucket": {"id": 10, "name": "Basecamp MCP", "type": "Project"},
        "todolist": {"id": 20, "name": "OAuth tasks", "type": "Todolist"},
        "creator": {"id": 30, "name": "Yuriy"},
        "assignees": [{"id": 31, "name": "Dev"}],
    }


@pytest.mark.anyio
async def test_get_todos_returns_compact_todo_context(monkeypatch):
    class FakeClient:
        def get_todos(self, project_id, todolist_id):
            assert project_id == "10"
            assert todolist_id == "20"
            return [
                {
                    "id": 1,
                    "content": "<p>Task <strong>one</strong></p>",
                    "description": "<div>Useful detail</div>",
                    "updated_at": "2026-05-14T10:00:00Z",
                    "raw_html": "<div>drop me</div>",
                }
            ]

    monkeypatch.setattr(basecamp_fastmcp, "_get_basecamp_client", lambda: FakeClient())

    result = await basecamp_fastmcp.get_todos("10", "20")

    assert result["status"] == "success"
    assert result["todos"] == [
        {
            "id": 1,
            "type": "Todo",
            "content": "Task one",
            "description": "Useful detail",
            "updated_at": "2026-05-14T10:00:00Z",
        }
    ]


@pytest.mark.anyio
async def test_get_project_todos_returns_latest_compact_context(monkeypatch):
    class FakeClient:
        def get_project_todos(self, project_id, status, limit):
            assert project_id == "10"
            assert status == "active"
            assert limit == 25
            return [
                {
                    "id": 2,
                    "type": "Todo",
                    "content": "<b>Newest task</b>",
                    "updated_at": "2026-05-14T11:00:00Z",
                    "bucket": {"id": 10, "name": "Basecamp MCP", "type": "Project"},
                }
            ]

    monkeypatch.setattr(basecamp_fastmcp, "_get_basecamp_client", lambda: FakeClient())

    result = await basecamp_fastmcp.get_project_todos("10", limit=25)

    assert result["status"] == "success"
    assert result["project_id"] == "10"
    assert result["count"] == 1
    assert result["todos"] == [
        {
            "id": 2,
            "type": "Todo",
            "content": "Newest task",
            "updated_at": "2026-05-14T11:00:00Z",
            "bucket": {"id": 10, "name": "Basecamp MCP", "type": "Project"},
        }
    ]


def test_compact_todos_truncates_long_html_description():
    long_description = f"<p>{'word ' * 300}</p>"

    compacted = compact_todos([{"id": 1, "content": "Task", "description": long_description}])

    assert compacted[0]["description"].endswith("...")
    assert "<p>" not in compacted[0]["description"]
    assert len(compacted[0]["description"]) <= 703
