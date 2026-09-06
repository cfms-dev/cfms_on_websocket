# Identity permissions API

Protocol version 24 replaces identity permission string lists with structured
grant and revocation entries. This is a breaking protocol change: protocol 23
clients and protocol 24 servers cannot mix during a rolling deployment.

## Permission entries

Every permission entry has four required fields:

```json
{
  "permission": "list_users",
  "granted": false,
  "start_time": 1787200000.0,
  "end_time": null
}
```

- `permission` is a string. Core and extension-defined names are accepted.
- `granted` is `true` for a grant and `false` for a revocation.
- `start_time` is an inclusive Unix timestamp in seconds.
- `end_time` is an inclusive Unix timestamp or `null` for no expiry. A finite
  end time must not be earlier than the start time.

Entries that have not started remain stored and visible. Expired entries remain
stored and visible during the configured retention period, then may be removed
by background or operator-triggered cleanup. Neither kind affects authorization.
For active entries, every revocation takes precedence over every grant. A user's
effective permissions therefore equal all active direct and group grants minus
all active direct and group revocations.

The default retention period is 30 days and is configured under
`identity.permission_retention` in `config.toml`. Cleanup never removes an entry
whose `end_time` is `null`, including permanent revocations.

Operators can preview or run the same cleanup policy explicitly:

```console
maintain permission purge-expired --dry-run
maintain permission purge-expired --yes
```

Expired-entry cleanup always runs as the system-managed
`builtin.permission_cleanup` interval task. Its interval is reconciled from
`identity.permission_retention.cleanup_interval_seconds` and it is not exposed as
an operator-editable schedule. Disabling the scheduling management extension does
not affect this task.

## Write actions

The following authenticated actions accept only structured entries in their
`data.permissions` array:

| Action | Required permission | Behavior |
| --- | --- | --- |
| `create_user` | `create_user` | Sets the new user's direct entries. |
| `change_user_permissions` | `set_user_permissions` | Replaces all direct entries for the user. |
| `create_group` | `create_group` | Sets the new group's entries. |
| `change_group_permissions` | `set_group_permissions` | Replaces all entries for the group. |

For example:

```json
{
  "action": "change_user_permissions",
  "data": {
    "username": "alice",
    "permissions": [
      {
        "permission": "list_users",
        "granted": true,
        "start_time": 1787200000.0,
        "end_time": null
      },
      {
        "permission": "delete_document",
        "granted": false,
        "start_time": 1787200000.0,
        "end_time": 1787800000.0
      }
    ]
  }
}
```

Each change action is a complete replacement. Omitting an existing entry from
the submitted list deletes that entry. Strings, missing fields, unknown fields,
wrong JSON types, and reversed time windows return `400`.

## Read actions

`get_user_info` and each item returned by `list_users` expose:

- `permissions`: all direct structured permission entries;
- `effective_permissions`: final effective permission names;
- `effective_own_permissions`: effective names from direct entries alone;
- `effective_inherited_permissions`: effective names from active group entries.

`get_group_info` and each item returned by `list_groups` expose structured
`permissions` plus `effective_permissions`. The former protocol 23
`own_permissions` and `inherited_permissions` response fields no longer exist.

## Migrating from protocol 23

Replace a permanent grant such as:

```json
"permissions": ["list_users"]
```

with:

```json
"permissions": [
  {
    "permission": "list_users",
    "granted": true,
    "start_time": 0.0,
    "end_time": null
  }
]
```

When reading users or groups, use `effective_permissions` for the former
effective string list and use `permissions` when editing the raw entries.
