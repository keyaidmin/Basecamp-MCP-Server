from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List


def parse_basecamp_time(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def comment_time(comment: Dict[str, Any]) -> datetime:
    value = comment.get("updated_at") or comment.get("created_at")
    if not value:
        return datetime.min.replace(tzinfo=timezone.utc)
    return parse_basecamp_time(value)


def select_recent_comments(
    comments: List[Dict[str, Any]],
    days: int,
    fallback_count: int,
    now: datetime | None = None,
) -> List[Dict[str, Any]]:
    if not comments:
        return []

    reference = now or datetime.now(timezone.utc)
    cutoff = reference - timedelta(days=days)
    sorted_comments = sorted(comments, key=comment_time, reverse=True)
    recent = [comment for comment in sorted_comments if comment_time(comment) >= cutoff]
    if recent:
        return recent[:fallback_count]
    return sorted_comments[:fallback_count]
