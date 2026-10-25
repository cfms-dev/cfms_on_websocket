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
an operator-editable schedule.

## Restoring default group permission records

The maintenance CLI compares the current code's default permissions for `user`
and `sysop` with database records. Preview all default groups, or select one or
more groups with repeatable `--group` options:

```console
uv run --locked maintain permission sync-defaults --dry-run
uv run --locked maintain permission sync-defaults --group sysop --dry-run
```

The report lists each selected group's default count, recorded count, and missing
permission names. A recorded permission may be revoked, expired, or not yet
active; the comparison checks record presence, not effective authorization.
Missing groups are reported and skipped, without recreating groups or memberships.
Unknown group names are rejected.

Stop **all server instances sharing the database** before applying changes:

```console
uv run --locked maintain permission sync-defaults
uv run --locked maintain permission sync-defaults --group user --group sysop --yes
```

Without `--yes`, the command previews the differences and asks for confirmation.
`--dry-run` never inserts permission records, including when combined with `--yes`,
and can run while the server is online. Applying changes acquires the existing
runtime-directory lock; a running server, another holder of that lock, or an
unfinished deployment prevents the write. This lock coordinates one runtime
directory only, not other machines or other directories sharing the database.

A permission is missing only if no record exists for its `(group_name, permission)`
pair. Existing grants, revocations, validity windows, and duplicate records remain
unchanged. Missing permissions are inserted as permanent grants with
`granted=true`, `start_time=0.0`, and `end_time=null`. Additional permissions,
custom groups, display names, direct user permissions, and memberships are preserved.

The command checks the preview again under the lock, then inserts all missing
records in one transaction. Changed differences require a new preview; database
failures roll back all inserts. Repeating a completed synchronization adds nothing.
Successful previews, synchronization, and skipped missing groups exit with `0`;
cancellation or runtime failures exit with `1`; invalid arguments exit with `2`.

The tool cannot distinguish a newly introduced default permission from a record
an administrator deliberately deleted. If deletion or expired-entry cleanup leaves
no record for a default permission, synchronization restores it. It does not run
automatically on startup, replace Alembic schema upgrades, or restore effective
access when a grant is blocked by an existing revocation.

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
    "user_id": "aabbccdd-0000-4000-8000-000000000001",
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

Since protocol 28, `change_user_permissions` requires the account's `user_id`.
Obtain it from `create_user`, `list_users`, or `get_user_info`; see
[account identity](USER_IDS.md#protocol-28-user-management).

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
