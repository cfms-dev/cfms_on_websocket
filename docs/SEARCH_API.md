# Search API Documentation

## Overview

The Search API searches documents and directories by name. The authenticated
user must have the `search` permission, either directly or through a group.
Results are then filtered by the user's read access, sorted deterministically,
and returned with cursor pagination.

## Endpoint

**Action:** `core.search.query`

**Authentication:** Required, with the `search` permission

## Request Format

```json
{
    "action": "core.search.query",
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
| `query` | string | Yes | - | Case-insensitive literal partial match term. Whitespace-only queries are rejected. |
| `page_size` | integer | No | 128 | Maximum number of items to return. Range: 1-128. |
| `cursor` | string/null | No | null | Encrypted cursor returned by the previous page. Omit or use null for the first page. |
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
                "created_time": 1234567890.123,
                "effective_mask": 1049603
            },
            {
                "type": "document",
                "id": "doc_id_1",
                "name": "Document Title",
                "parent_id": "folder_id",
                "created_time": 1234567890.123,
                "last_modified": 1234567891.456,
                "size": 1024,
                "effective_mask": 1040
            }
        ],
        "parent_effective_masks": {
            "parent_folder_id": 1049603,
            "folder_id": 1
        },
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
| `parent_effective_masks` | object | Map from each distinct non-null `parent_id` appearing in `items` to that parent directory's 21-bit projected `effective_mask`. |
| `page_size` | integer | Page size used for the request. |
| `next_cursor` | string/null | Encrypted cursor for the next page, or null when no next page exists. |
| `has_more` | boolean | Whether another page is available. |
| `query` | string | Trimmed query that was executed. |

Each item includes `type`, `id`, `name`, `parent_id`, `created_time`, and
`effective_mask` (a 21-bit CEP-0002 `AtomicOp` integer bitmask indicating the
operations the authenticated user is currently permitted to perform on that
node; see [Protocol 32 migration](PROTOCOL_32_MIGRATION.md)).
Document items additionally include `last_modified` and `size`.

`parent_effective_masks` contains one entry per unique non-null `parent_id`
referenced by the returned `items` page (never including lookahead items beyond
the page boundary, and omitting `null` when the root directory `/` itself
appears in `items`). Each entry follows the same Protocol 32 projection and
global gate rules as directory `effective_mask` values, allowing clients to
determine whether the caller can access a result's containing directory (for
example, `LIST_DIRECTORY` or `READ_METADATA`) without issuing extra requests.

## Cursor Rules

`cursor` is an encrypted opaque server-generated token. It is bound to the
original search parameters, including query, target type filters, and sorting.
Reusing a cursor with different parameters returns 400.

The cursor token format is internal and not part of the public protocol. Clients
must store and replay the complete token as returned, without decoding,
modifying, or depending on individual fields.

To fetch the next page, repeat the same request data and set `cursor` to the
previous response's `next_cursor`.

## Error Responses

| Code | Description |
|------|-------------|
| 400 | Invalid query, invalid sort parameter, invalid page size, or invalid cursor. |
| 401 | Authentication required. |
| 403 | The authenticated user does not have the `search` permission. |

## Notes

- Search terms are matched literally. Characters with special meaning in SQL
  patterns, including `%` and `_`, do not act as wildcards; `/`, quotes, and
  other punctuation are also matched as ordinary characters.
- The global `search` permission controls whether a user may invoke this API.
  CACL DACL policies (including inheritance, scopes, validity windows,
  deny-overrides, and ancestor `TRAVERSE` checks unless bypassed via
  `bypass_traverse_checking` or `bypass_dacl`) then determine which matching
  objects appear in the response (`READ_CONTENT` or `READ_METADATA` for
  documents; `LIST_DIRECTORY` or `READ_METADATA` for directories).
- Permission filtering is applied before pagination, so page boundaries and
  `has_more` are calculated from visible candidates.
- Documents without active revisions are excluded.
- Empty results return `items: []`, `parent_effective_masks: {}`, `has_more: false`, and `next_cursor: null`.
