# Protocol 32: CACL effective permission bitmasks

Protocol 32 adds `effective_mask` — a 21-bit CEP-0002 `AtomicOp` integer bitmask
representing the operations the authenticated caller is currently permitted to
perform on a directory or document — to file-domain read, listing, search,
revision, creation, and DACL responses.

## Bit layout

Bit offsets match `cacl_compiler.AtomicOp` (`0`..`20`, mask range `0x000000`..`0x1FFFFF`):

| Bit | Hex | Operation | Target | State | Notes |
| --- | --- | --- | --- | --- | --- |
| 0 | `0x000001` | `TRAVERSE` | directory | normal | Required on normal ancestors unless `bypass_traverse_checking` or `bypass_dacl` applies. |
| 1 | `0x000002` | `LIST_DIRECTORY` | directory | normal | `core.directory.list` |
| 2 | `0x000004` | `CREATE_DOCUMENT` | directory | normal | `core.document.create` / reparent destination |
| 3 | `0x000008` | `CREATE_DIRECTORY` | directory | normal | `core.directory.create` / reparent destination |
| 4 | `0x000010` | `READ_CONTENT` | document | normal | `core.document.get` and current revision download |
| 5 | `0x000020` | `WRITE_CONTENT` | document | normal | `core.document.upload` |
| 6 | `0x000040` | `LIST_REVISIONS` | document | normal | `core.document.revision.list` |
| 7 | `0x000080` | `READ_REVISION` | document | normal | `core.document.revision.get` (historical revisions) |
| 8 | `0x000100` | `SET_CURRENT_REVISION` | document | normal | `core.document.revision.current.set` |
| 9 | `0x000200` | `DELETE_REVISION` | document | normal | Also gated by global `delete_revision` permission. |
| 10 | `0x000400` | `READ_METADATA` | both | normal | `core.{directory,document}.info.get` |
| 11 | `0x000800` | `WRITE_METADATA` | both | normal | `core.document.tag.set` |
| 12 | `0x001000` | `RENAME` | both | normal | Cleared on root directory `/`. |
| 13 | `0x002000` | `REPARENT` | both | normal | Cleared on root directory `/`; destination still requires `CREATE_*`. |
| 14 | `0x004000` | `DELETE` | both | normal | Cleared on root directory `/`. |
| 15 | `0x008000` | `DIRECTORY_DELETE_CHILD` | directory | normal | Cleared on root directory `/`; overrides descendant `DELETE` checks on directory soft-delete. |
| 16 | `0x010000` | `LIST_DELETED` | directory | both | `core.directory.deleted_item.list` |
| 17 | `0x020000` | `RESTORE` | both | soft_deleted | `core.{directory,document}.restore` |
| 18 | `0x040000` | `PURGE` | both | soft_deleted | Also gated by global `purge` permission. |
| 19 | `0x080000` | `READ_DACL` | both | normal | `core.{directory,document}.dacl.get` |
| 20 | `0x100000` | `WRITE_DACL` | both | normal | `core.{directory,document}.dacl.set` and initial `dacl` on create. |

## Projection and security invariants

Every emitted `effective_mask` is computed as:

```text
effective_mask = raw_effective_mask & applicable_ops_mask(type, state, is_root) & global_gate_ops_mask(user)
```

- **Collapsed single mask**: Only the final `allow & ~deny` bitmask is returned.
  `allow_mask`, `deny_mask`, `inherit`, rule counts, and future/expiry timestamps
  are never exposed.
- **Target, state, and root clamping**: Bits inapplicable to the node's type,
  lifecycle state (`normal` vs `soft_deleted`), or root directory `/` are always
  cleared (`0`), including for actors holding `bypass_dacl`.
- **Global gate intersection**: `PURGE` (bit 18) is cleared unless the actor holds
  global `purge`, and `DELETE_REVISION` (bit 9) is cleared unless the actor holds
  global `delete_revision`, including for actors holding `bypass_dacl`.
- **Parent `TRAVERSE` enforcement**: In `core.directory.list` (and in
  `core.directory.deleted_item.list` when the listed folder is `normal`), if
  ancestor traverse checking is active and the caller lacks `TRAVERSE` on the
  listed folder, all child items receive `effective_mask: 0` without loading
  child DACL policies. When listing deleted items inside a `soft_deleted` folder,
  `TRAVERSE` is skipped on the soft-deleted folder itself, matching CACL runtime
  evaluation.
- **No descendant scanning**: Directory `DELETE`, `PURGE`, and `RESTORE` bits
  reflect only the directory itself (never probing hidden descendants). Clients
  should treat `effective_mask` as a pre-flight UI hint; the server remains the
  authoritative enforcement point on every request.
- **Error responses**: Error responses (`401`, `403`, `404`, `409`) never include
  `effective_mask`.

## Updated endpoints

| Action | Location of `effective_mask` |
| --- | --- |
| `core.directory.list` | Top-level `data.effective_mask` (listed folder) and each `data.items[].effective_mask` |
| `core.directory.deleted_item.list` | Top-level `data.effective_mask` (target folder) and each `data.items[].effective_mask` |
| `core.directory.info.get` | `data.effective_mask` |
| `core.document.info.get` | `data.effective_mask` |
| `core.search.query` | Each `data.items[].effective_mask` |
| `core.document.revision.list` | Top-level `data.effective_mask` (document) |
| `core.directory.dacl.get` | `data.effective_mask` |
| `core.document.dacl.get` | `data.effective_mask` |
| `core.directory.dacl.set` | `data.effective_mask` (evaluated against the newly saved policy) |
| `core.document.dacl.set` | `data.effective_mask` (evaluated against the newly saved policy) |
| `core.directory.create` | `data.effective_mask` (including `exists_ok: true` when hitting an existing readable directory) |
| `core.document.create` | `data.effective_mask` |
