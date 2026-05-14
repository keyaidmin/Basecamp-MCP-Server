import hashlib
import os
import sqlite3
import time
from typing import Any, Dict, Iterable, List, Optional


DB_PATH = os.getenv(
    "BASECAMP_CONTEXT_DB",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "basecamp_context.sqlite3"),
)


def init_context_db(db_path: str = DB_PATH) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS todo_comment_context (
                project_id TEXT NOT NULL,
                todo_id TEXT NOT NULL,
                comment_hash TEXT NOT NULL,
                latest_comment_at TEXT,
                summary TEXT NOT NULL,
                created_at INTEGER NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL,
                total_comments INTEGER,
                fetched_comments INTEGER,
                has_more_comments INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (project_id, todo_id)
            )
            """
        )
        existing_columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(todo_comment_context)").fetchall()
        }
        migrations = {
            "created_at": "ALTER TABLE todo_comment_context ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0",
            "total_comments": "ALTER TABLE todo_comment_context ADD COLUMN total_comments INTEGER",
            "fetched_comments": "ALTER TABLE todo_comment_context ADD COLUMN fetched_comments INTEGER",
            "has_more_comments": "ALTER TABLE todo_comment_context ADD COLUMN has_more_comments INTEGER NOT NULL DEFAULT 0",
        }
        for column, statement in migrations.items():
            if column not in existing_columns:
                conn.execute(statement)


def comment_signature(comments: Iterable[Dict[str, Any]]) -> str:
    digest = hashlib.sha256()
    for comment in comments:
        digest.update(str(comment.get("id", "")).encode("utf-8"))
        digest.update(str(comment.get("updated_at") or comment.get("created_at") or "").encode("utf-8"))
        digest.update(str(comment.get("content", "")).encode("utf-8"))
    return digest.hexdigest()


def latest_comment_at(comments: Iterable[Dict[str, Any]]) -> Optional[str]:
    timestamps = [
        comment.get("updated_at") or comment.get("created_at")
        for comment in comments
        if comment.get("updated_at") or comment.get("created_at")
    ]
    return max(timestamps) if timestamps else None


def summarize_comments(comments: List[Dict[str, Any]], max_chars: int = 1400) -> str:
    if not comments:
        return "No comments fetched for this todo."

    lines = []
    for comment in comments:
        author = (comment.get("creator") or {}).get("name") or "Unknown"
        timestamp = comment.get("updated_at") or comment.get("created_at") or "unknown time"
        content = comment.get("content") or ""
        if not content:
            continue
        lines.append(f"- {timestamp} by {author}: {content}")

    summary = "\n".join(lines) or "Fetched comments had no readable text."
    if len(summary) <= max_chars:
        return summary
    return f"{summary[:max_chars].rstrip()}..."


def load_cached_summary(
    project_id: str,
    todo_id: str,
    comment_hash: str,
    db_path: str = DB_PATH,
) -> Optional[Dict[str, Any]]:
    init_context_db(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT summary, latest_comment_at, created_at, updated_at, total_comments,
                   fetched_comments, has_more_comments
            FROM todo_comment_context
            WHERE project_id = ? AND todo_id = ? AND comment_hash = ?
            """,
            (str(project_id), str(todo_id), comment_hash),
        ).fetchone()
    if row is None:
        return None
    return {
        "summary": row["summary"],
        "latest_comment_at": row["latest_comment_at"],
        "cached": True,
        "cache_created_at": row["created_at"],
        "cache_updated_at": row["updated_at"],
        "total_comments": row["total_comments"],
        "fetched_comments": row["fetched_comments"],
        "has_more_comments": bool(row["has_more_comments"]),
    }


def save_summary(
    project_id: str,
    todo_id: str,
    comment_hash: str,
    latest_at: Optional[str],
    summary: str,
    total_comments: Optional[int] = None,
    fetched_comments: Optional[int] = None,
    has_more_comments: bool = False,
    db_path: str = DB_PATH,
) -> None:
    init_context_db(db_path)
    now = int(time.time())
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO todo_comment_context (
                project_id, todo_id, comment_hash, latest_comment_at, summary, created_at,
                updated_at, total_comments, fetched_comments, has_more_comments
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(project_id, todo_id) DO UPDATE SET
                comment_hash = excluded.comment_hash,
                latest_comment_at = excluded.latest_comment_at,
                summary = excluded.summary,
                updated_at = excluded.updated_at,
                total_comments = excluded.total_comments,
                fetched_comments = excluded.fetched_comments,
                has_more_comments = excluded.has_more_comments
            """,
            (
                str(project_id),
                str(todo_id),
                comment_hash,
                latest_at,
                summary,
                now,
                now,
                total_comments,
                fetched_comments,
                1 if has_more_comments else 0,
            ),
        )


def load_or_create_summary(
    project_id: str,
    todo_id: str,
    comments: List[Dict[str, Any]],
    force_refresh: bool = False,
    total_comments: Optional[int] = None,
    fetched_comments: Optional[int] = None,
    has_more_comments: bool = False,
    db_path: str = DB_PATH,
) -> Dict[str, Any]:
    signature = comment_signature(comments)
    cached = None if force_refresh else load_cached_summary(project_id, todo_id, signature, db_path=db_path)
    if cached is not None:
        return cached

    latest_at = latest_comment_at(comments)
    summary = summarize_comments(comments)
    save_summary(
        project_id,
        todo_id,
        signature,
        latest_at,
        summary,
        total_comments=total_comments,
        fetched_comments=fetched_comments,
        has_more_comments=has_more_comments,
        db_path=db_path,
    )
    now = int(time.time())
    return {
        "summary": summary,
        "latest_comment_at": latest_at,
        "cached": False,
        "cache_created_at": now,
        "cache_updated_at": now,
        "total_comments": total_comments,
        "fetched_comments": fetched_comments,
        "has_more_comments": has_more_comments,
    }
