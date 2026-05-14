import re
from html import unescape
from typing import Any, Dict, Iterable, List, Optional

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None


def html_to_text(value: Optional[str], max_length: int = 700) -> Optional[str]:
    if not value:
        return None

    if BeautifulSoup is not None:
        soup = BeautifulSoup(value, "html.parser")
        for br in soup.find_all("br"):
            br.replace_with("\n")
        text = soup.get_text(" ")
    else:
        text = re.sub(r"(?i)<\s*br\s*/?\s*>", "\n", value)
        text = re.sub(r"(?i)</\s*(p|div|li|tr|h[1-6])\s*>", "\n", text)
        text = re.sub(r"<[^>]+>", "", text)
    text = unescape(text)
    text = re.sub(r"[ \t\r\f\v\u00a0]+", " ", text)
    text = re.sub(r" *\n *", "\n", text)
    text = re.sub(r"\n\s*\n+", "\n", text)
    text = text.strip()

    if len(text) <= max_length:
        return text

    return f"{text[:max_length].rstrip()}..."


def compact_person(person: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not isinstance(person, dict):
        return None

    return {
        key: value
        for key, value in {
            "id": person.get("id"),
            "name": person.get("name"),
            "email_address": person.get("email_address"),
        }.items()
        if value is not None
    }


def compact_people(people: Optional[Iterable[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    if not people:
        return []

    compacted = [compact_person(person) for person in people]
    return [person for person in compacted if person]


def compact_reference(value: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not isinstance(value, dict):
        return None

    return {
        key: item
        for key, item in {
            "id": value.get("id"),
            "name": value.get("name") or value.get("title"),
            "type": value.get("type"),
        }.items()
        if item is not None
    }


def compact_todo(todo: Dict[str, Any]) -> Dict[str, Any]:
    content = html_to_text(
        todo.get("content")
        or todo.get("plain_text_content")
        or todo.get("title")
        or todo.get("name"),
        max_length=300,
    )
    description = html_to_text(
        todo.get("description")
        or todo.get("plain_text_description")
        or todo.get("notes")
        or todo.get("details")
    )

    compacted = {
        "id": todo.get("id"),
        "type": todo.get("type", "Todo"),
        "content": content,
        "description": description,
        "completed": todo.get("completed"),
        "status": todo.get("status"),
        "due_on": todo.get("due_on"),
        "starts_on": todo.get("starts_on"),
        "created_at": todo.get("created_at"),
        "updated_at": todo.get("updated_at"),
        "app_url": todo.get("app_url"),
        "web_url": todo.get("web_url"),
        "bucket": compact_reference(todo.get("bucket") or todo.get("project")),
        "todolist": compact_reference(todo.get("parent") or todo.get("todolist")),
        "creator": compact_person(todo.get("creator")),
        "assignees": compact_people(todo.get("assignees")),
    }

    return {
        key: value
        for key, value in compacted.items()
        if value not in (None, "", [], {})
    }


def compact_todos(todos: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [compact_todo(todo) for todo in todos]


def compact_comment(comment: Dict[str, Any]) -> Dict[str, Any]:
    content = html_to_text(
        comment.get("content")
        or comment.get("plain_text_content")
        or comment.get("body")
        or comment.get("description"),
        max_length=500,
    )

    compacted = {
        "id": comment.get("id"),
        "content": content,
        "created_at": comment.get("created_at"),
        "updated_at": comment.get("updated_at"),
        "app_url": comment.get("app_url"),
        "web_url": comment.get("web_url"),
        "creator": compact_person(comment.get("creator")),
    }

    return {
        key: value
        for key, value in compacted.items()
        if value not in (None, "", [], {})
    }


def compact_comments(comments: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [compact_comment(comment) for comment in comments]
