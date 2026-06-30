# Search API Documentation

## Overview

The Search API searches documents and directories by name. Results are filtered
by the authenticated user's read access, sorted deterministically, and returned
with cursor pagination.

## Endpoint

**Action:** `search`

**Authentication:** Required

## Request Format

```json
{
    "action": "search",
    "username": "<username>",
    "token": "<auth_token>",
    "data": {
        "query": "<search_query>",
        "page_size": 128,
        "cursor": null,
        "sort_by": "name",
        "sort_order": "asc",
        "search_documents": true,
        "search_directories": true
    }
}
```

## Request Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `query` | string | Yes | - | Case-insensitive partial match term. Whitespace-only queries are rejected. |
| `page_size` | integer | No | 128 | Maximum number of items to return. Range: 1-128. |
| `cursor` | string/null | No | null | Cursor returned by the previous page. Omit or use null for the first page. |
| `sort_by` | string | No | `name` | One of `name`, `created_time`, `size`, `last_modified`. |
| `sort_order` | string | No | `asc` | `asc` or `desc`. |
| `search_documents` | boolean | No | true | Include matching documents. |
| `search_directories` | boolean | No | true | Include matching directories. |

## Success Response

```json
{
    "code": 200,
    "message": "Search completed successfully. Found 2 result(s).",
    "data": {
        "items": [
            {
                "type": "directory",
                "id": "dir_id_1",
                "name": "Directory Name",
                "parent_id": "parent_folder_id",
                "created_time": 1234567890.123
            },
            {
                "type": "document",
                "id": "doc_id_1",
                "name": "Document Title",
                "parent_id": "folder_id",
                "created_time": 1234567890.123,
                "last_modified": 1234567891.456,
                "size": 1024
            }
        ],
        "page_size": 128,
        "next_cursor": null,
        "has_more": false,
        "query": "search term"
    }
}
```

## Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `items` | array | Matching documents and directories visible to the user. |
| `page_size` | integer | Page size used for the request. |
| `next_cursor` | string/null | Cursor for the next page, or null when no next page exists. |
| `has_more` | boolean | Whether another page is available. |
| `query` | string | Trimmed query that was executed. |

Each item includes `type`, `id`, `name`, `parent_id`, and `created_time`.
Document items additionally include `last_modified` and `size`.

## Cursor Rules

`cursor` is an opaque server-generated token. It is bound to the original search
parameters, including query, target type filters, and sorting. Reusing a cursor
with different parameters returns 400.

To fetch the next page, repeat the same request data and set `cursor` to the
previous response's `next_cursor`.

## Error Responses

| Code | Description |
|------|-------------|
| 400 | Invalid query, invalid sort parameter, invalid page size, or invalid cursor. |
| 401 | Authentication required. |
| 403 | Invalid user/token or access denied. |

## Notes

- Permission filtering is applied before pagination.
- Documents without active revisions are excluded.
- Empty results return `items: []`, `has_more: false`, and `next_cursor: null`.
