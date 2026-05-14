# Basecamp Status Update Tool Plan

## Goal

Add a low-token status update tool for a given Basecamp project. The tool should return recent updated todos and compact recent comments for those todos, while avoiding raw HTML and repeated full comment history.

## Current Behavior

- `get_project_todos` returns compact latest updated todos from `projects/recordings.json`.
- `get_comments` returns raw comment records from one comments page.
- Search/status flows can still force the model to read too much repeated Basecamp HTML and comment history.

## API Shape To Use

- Recent project todos:
  - `GET /projects/recordings.json`
  - Params: `type=Todo`, `bucket=<project_id>`, `status=active`, `sort=updated_at`, `direction=desc`
- Todo comments:
  - `GET /buckets/<project_id>/recordings/<todo_id>/comments.json`
  - Use geared pagination only when necessary. Page 1 is enough for recent context in most cases.

## Implementation

1. Add clear parsers:
   - Add `beautifulsoup4` for robust HTML-to-text conversion.
   - Keep regex fallback so tests do not depend on parser internals.

2. Add compact comment context:
   - Extract only `id`, `content`, `created_at`, `updated_at`, `creator`, and useful URLs.
   - Strip HTML and truncate long bodies.

3. Add local context database:
   - SQLite file: `basecamp_context.sqlite3`.
   - Table keyed by `(project_id, todo_id)`.
   - Store comment IDs hash, latest comment timestamp, compact summary, and update time.
   - Summary is deterministic and local: compact digest of all fetched comment text, not an LLM call.

4. Add status update tool:
   - Tool name: `get_project_status_update`.
   - Inputs:
     - `project_id`
     - `todo_limit` default `10`, max `25`
     - `comments_per_todo` default `5`, max `10`
     - `days` default `7`
   - For each recent todo:
     - Fetch page 1 comments.
     - Return comments from the last `days`.
     - If no comments in that window, return last `3-5` comments.
     - Include cached summary for the full fetched comment context.

5. Token-control rules:
   - Never return raw HTML.
   - Never return full Basecamp records.
   - Cap todo count and comment count.
   - Return summary plus recent comments, not all comments.

## Validation

- Unit tests for HTML parsing, comment compaction, summary cache, and status update response shape.
- Focused pytest run for new status tests plus existing todo/search tests.
- Full test suite, noting the known unrelated CLI subprocess timeout if it remains.
- Real Basecamp smoke check against the Talented project:
  - Verify response keys/counts/order only.
  - Do not print sensitive comment bodies into logs or final response.
