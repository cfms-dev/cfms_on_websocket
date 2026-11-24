# Protocol 32: CACL DACL authorization and reparent semantics

Upgrade clients and servers together. Protocol 32 migrates filesystem
authorization to **CEP-0002 (CFMS Access Control Language / CACL)**, removes the
legacy JSON access-rule, object-access-entry, and user-block systems, overhauls
global permissions, and renames move actions to `reparent`.

## Action changes

### Added / Replaced actions

| Protocol 31 action | Protocol 32 action | Notes |
| --- | --- | --- |
| `core.document.access_rule.get` | `core.document.dacl.get` | Returns `{dacl, inherit, fingerprint}` (plus `annotated_dacl` when `annotate_users: true`). |
| `core.document.access_rule.set` | `core.document.dacl.set` | Accepts `{document_id, dacl, allow_self_lockout?}`. Returns `{dacl, inherit, fingerprint, diagnostics, self_lockout_warning}`. |
| `core.directory.access_rule.get` | `core.directory.dacl.get` | Returns `{dacl, inherit, fingerprint}` (plus `annotated_dacl` when `annotate_users: true`). |
| `core.directory.access_rule.set` | `core.directory.dacl.set` | Accepts `{directory_id, dacl, allow_self_lockout?}`. Returns `{dacl, inherit, fingerprint, diagnostics, self_lockout_warning}`. |
| `core.document.move` | `core.document.reparent` | Pure parent-change (`REPARENT` on source + `CREATE_DOCUMENT` on destination). |
| `core.directory.move` | `core.directory.reparent` | Pure parent-change (`REPARENT` on source + `CREATE_DIRECTORY` on destination). |

### Removed actions

- `core.document.move`, `core.directory.move`
- `core.document.access_rule.get`, `core.document.access_rule.set`
- `core.directory.access_rule.get`, `core.directory.access_rule.set`
- `core.access.entry.grant`, `core.access.entry.revoke`, `core.access.entry.list`
- `core.user.block.create`, `core.user.block.delete`, `core.user.block.update`, `core.user.block.list`

## Behavioral changes

- **DACL evaluation**: Every file-domain operation is evaluated against the
  node's compiled CACL DACL chain (default-deny, deny-overrides, `inherit on | off`,
  scopes `self`/`dirs`/`docs`/`all`, half-open UTC time windows `[from, until)`,
  and ancestor `TRAVERSE` enforcement).
- **Soft anti-lockout**: `core.{document,directory}.dacl.set` and `create` with
  an initial `dacl` simulate whether the actor retains `WRITE_DACL`. If the save
  would lock the actor out and the actor does not hold `bypass_dacl`, the server
  returns `409` with `{"self_lockout_warning": true, "diagnostics": [...]}`
  unless `allow_self_lockout: true` is provided.
- **Initial DACL on creation**: Providing `dacl` to `core.document.create` or
  `core.directory.create` requires `WRITE_DACL` on the parent directory (or
  global `bypass_dacl`) in addition to `CREATE_DOCUMENT` / `CREATE_DIRECTORY`.
- **Atomic directory soft-delete**: `core.directory.delete` requires `DELETE` on
  the target directory and either `DIRECTORY_DELETE_CHILD` on the target or
  `DELETE` on every non-deleted descendant. Authorization failure returns `403`
  atomically with no partial deletion.
- **Info responses**: `core.document.info.get` and `core.directory.info.get` no
  longer return `access_rules` or `info_code`. `core.document.info.get` is gated
  by `READ_METADATA` and always includes `metadata`.
- **Revisions**: `core.document.revision.get` checks `READ_CONTENT` for the
  current revision and `READ_REVISION` for historical revisions.

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

Run `cfms-ctl database upgrade` (Alembic revision `a66108639ed7`). The migration
creates `dacl_rules`, `dacl_rule_clauses`, and `dacl_rule_atoms`, drops the
legacy compiled-access-rule, object-access-entry, and user-block tables, seeds
the default root `/` DACL, grants `bypass_dacl` and `bypass_traverse_checking`
to `sysop`, prunes removed permissions, and deletes the obsolete
`access.enable_access_recursive_check` option row.
