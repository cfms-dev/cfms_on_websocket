# Audit log API

The `view_audit_logs` action returns audit entries in reverse chronological
order. It requires an authenticated request with the `view_audit_logs`
permission and uses a request-rate cost of 3.

## Request

```json
{
  "action": "view_audit_logs",
  "username": "admin",
  "token": "<token>",
  "nonce": "<unique nonce>",
  "timestamp": 1786600000,
  "data": {
    "page_size": 50,
    "cursor": null,
    "filters": ["login", "create_directory"]
  }
}
```

All fields in `data` are optional:

| Field | Type | Behavior |
| --- | --- | --- |
| `page_size` | integer | Number of entries to return, from 1 through 128. Defaults to 128. |
| `cursor` | string or null | Opaque cursor returned by the previous page. |
| `filters` | array of strings | Exact audit action values combined with OR. An omitted or empty array does not filter by action. |

An unknown action value is valid and produces an empty page when no stored entry
matches it. Action values are the strings emitted by the server and its
extensions; they are not a closed enum.

## Response data

```json
{
  "items": [
    {
      "id": "<audit entry id>",
      "action": "create_directory",
      "username": "admin",
      "target": null,
      "data": null,
      "result": 0,
      "remote_address": "192.0.2.10",
      "logged_time": 1786600000.25
    }
  ],
  "page_size": 50,
  "next_cursor": "<opaque cursor>",
  "has_more": true
}
```

Entries are ordered by `logged_time` descending and then `id` descending. The
cursor expires after one hour and is bound to the action and filter values used
to create it. Clients must repeat the same `filters` values when requesting the
next page. The order of those values may differ, but adding or removing a value
causes the server to reject the cursor with response code 400.

When there is no next page, `has_more` is `false` and `next_cursor` is `null`.
The cursor is internal and must be replayed without decoding or modifying it.

