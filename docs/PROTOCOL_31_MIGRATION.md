# Protocol 31: CACL authorization, reparenting, and audit exclusions

Upgrade clients and servers together. Relative to Protocol 30, Protocol 31
migrates filesystem authorization to **CEP-0002 (CFMS Access Control Language / CACL)**,
removes legacy access rules, access entries, and user blocks, overhauls
file-domain permissions, renames move actions to `reparent`, and adds action
exclusions to audit listing.

## Action changes

### Replaced actions

Old actions have no compatibility aliases; update clients and any
`security.request_rate_control` `action_costs` overrides together.

| Protocol 30 action | Protocol 31 action | Notes |
| --- | --- | --- |
| `core.document.access_rule.get` | `core.document.dacl.get` | Accepts `{document_id, annotate_users?}`; returns `{dacl, inherit, fingerprint}` (plus `annotated_dacl` when `annotate_users: true`). |
| `core.document.access_rule.set` | `core.document.dacl.set` | Accepts `{document_id, dacl, allow_self_lockout?}`; returns `{dacl, inherit, fingerprint, diagnostics, self_lockout_warning}`. |
| `core.directory.access_rule.get` | `core.directory.dacl.get` | Accepts `{directory_id, annotate_users?}`; returns `{dacl, inherit, fingerprint}` (plus `annotated_dacl` when `annotate_users: true`). |
| `core.directory.access_rule.set` | `core.directory.dacl.set` | Accepts `{directory_id, dacl, allow_self_lockout?}`; returns `{dacl, inherit, fingerprint, diagnostics, self_lockout_warning}`. |
| `core.document.move` | `core.document.reparent` | Pure parent change (`REPARENT` on source + `CREATE_DOCUMENT` on destination). |
| `core.directory.move` | `core.directory.reparent` | Pure parent change (`REPARENT` on source + `CREATE_DIRECTORY` on destination). |

### Removed actions

In addition to the replaced Protocol 30 actions above, these actions are
removed without replacement:

- `core.access.entry.grant`, `core.access.entry.revoke`, `core.access.entry.list`
- `core.user.block.create`, `core.user.block.delete`, `core.user.block.update`, `core.user.block.list`

## CACL authorization and file-domain changes

- **DACL evaluation**: File-domain operations evaluate against the node's compiled
  CACL DACL chain (default-deny, deny-overrides, `inherit on | off`, scopes
  `self`/`dirs`/`docs`/`all`, half-open UTC time windows `[from, until)`, and
  ancestor `TRAVERSE` enforcement).
- **Initial DACL on creation**: `core.document.create` and `core.directory.create`
  replace `access_rules` and `inherit_parent` with optional `dacl` and
  `allow_self_lockout`. Supplying `dacl` requires `WRITE_DACL` on the parent
  directory (or global `bypass_dacl`) in addition to `CREATE_DOCUMENT` /
  `CREATE_DIRECTORY`.
- **Soft anti-lockout**: `core.{document,directory}.dacl.set` and `create` with
  an initial `dacl` simulate whether the actor retains `WRITE_DACL`. If the save
  would lock the actor out and the actor lacks `bypass_dacl`, the server returns
  `409` with `{"self_lockout_warning": true, "diagnostics": [...]}` unless
  `allow_self_lockout: true` is supplied.
- **Atomic directory soft-delete**: `core.directory.delete` requires `DELETE` on
  the target directory and either `DIRECTORY_DELETE_CHILD` on the target or
  `DELETE` on every non-deleted descendant; authorization failure returns `403`
  atomically with no partial deletion.
- **Info responses**: `core.document.info.get` and `core.directory.info.get` are
  gated by `READ_METADATA` and no longer return `access_rules` or `info_code`.
  `core.document.info.get` always includes `metadata`.
- **Revisions**: `core.document.revision.get` checks `READ_CONTENT` for the
  current revision and `READ_REVISION` for historical revisions.

## Audit action exclusions

`core.audit.entry.list` adds optional `exclude_filters` (see
[Audit log API](AUDIT_LOG_API.md)). Queries match
`(no includes OR action IN filters) AND action NOT IN exclude_filters` before
sorting and cursor pagination:

- Both `filters` and `exclude_filters` match exact, case-sensitive action values
  (including unknown extension and historical values). Omitted or empty arrays
  impose no condition; when an action appears in both lists, exclusion wins.
- Cursors bind both arrays as sorted sets. Reordering or repeating values is
  allowed, but changing either distinct set with an existing cursor returns
  `400`. Protocol 30 cursors cannot be reused.
- Audit recording, response fields, permissions, and request-rate cost remain
  unchanged. The server applies no default exclusions (defaults such as
  excluding `core.audit.entry.list` and `core.setting.get` remain client-side
  preferences; clearing both lists returns all recorded actions).

## Permissions and database options

- **Added global permissions** (granted to `sysop` by default):
  `bypass_dacl`, `bypass_traverse_checking`.
- **Retained file-domain global gates**: `search`, `purge`, `delete_revision`.
- **Removed global permissions**: `manage_access`, `view_access_entries`,
  `block`, `unblock`, `list_user_blocks`, `view_access_rules`,
  `set_access_rules`, `super_create_document`, `super_create_directory`,
  `super_list_directory`, `move`, `create_document`, `delete_document`,
  `rename_document`, `create_directory`, `delete_directory`, `rename_directory`,
  `list_deleted_items`, `restore`, `view_metadata`, `set_metadata_tags`,
  `list_revisions`, `view_revision`, `set_current_revision`.
- **Database option**: `access.enable_access_recursive_check` is replaced by
  `access.bypass_traverse_checking` (default `false`).

## Database migration

Stop the server and back up its database before running:

```console
cfms-ctl database upgrade
```

Alembic revision `a66108639ed7` creates `dacl_rules`, `dacl_rule_clauses`, and
`dacl_rule_atoms`, drops the legacy compiled-access-rule, object-access-entry,
and user-block tables, seeds the default root `/` DACL, grants `bypass_dacl` and
`bypass_traverse_checking` to `sysop`, prunes removed permissions, and deletes
the obsolete `access.enable_access_recursive_check` option row. Historical audit
records remain unchanged.
