# Database configuration

The `options` table stores configuration groups identified by `(owner, option_key)`.
The core owns `core/server`; the brute-force lockdown extension owns
`brute_force_lockdown/policy`. Each group has a payload schema version, a positive
concurrency revision, a JSON object payload, and an update timestamp. Revision
zero represents an absent group when reading code defaults.

Database credentials, secrets, networking, providers, and the enabled extension
list remain in `config.toml`. The server name and the complete brute-force policy
are read from the database for each operation. File reloads do not override them.
No background options refresh or process-wide options cache is used.

## Upgrade an existing deployment

Stop the server before upgrading. For a shared database, stop every node and
prevent other maintenance commands from writing during migration. The local
runtime lock coordinates processes using one server directory; it is not a
cluster maintenance lock.

```powershell
uv run maintain database upgrade
uv run maintain config migrate-options --check
uv run maintain config migrate-options --yes
```

The migration preview validates `server.name` and
`extensions.brute_force_lockdown`, including a disabled extension's policy.
Writing inserts missing database groups, then removes those fields from TOML
using the existing atomic write and backup mechanism. It preserves comments on
other settings. Already imported identical groups are kept without another
revision. Conflicting database values block migration; use
`--discard-legacy --yes` to keep database values and remove old file settings.
If a group is missing, discarding its legacy value persists code defaults.

Database changes commit before TOML cleanup. If cleanup fails, the error reports
that stage and the same command can finish it safely. Startup refuses to proceed
while legacy fields remain. It never imports them automatically. An existing
database must already match the release's Alembic head; startup initializes and
stamps a genuinely empty database only.

## Read and update groups

```powershell
uv run maintain config options list
uv run maintain config options get core server
uv run maintain config options set core server server-options.json --expected-revision 1
uv run maintain config options reset core server --expected-revision 2
```

For example, `server-options.json` can contain `{"name": "My CFMS Server"}`.
Updates replace a complete group and validate it against the owning definition.
Use the revision from the latest read; a concurrent change rejects a stale write.
Use `--expected-revision 0` to create a missing group. Reset persists code
defaults and advances the revision. Writes and their audit entries share one
transaction; audit records contain changed field names and revisions, not values.

Listing and reading stored groups do not import extension code. Unknown,
disabled, and uninstalled owners remain visible. Writing an extension group
temporarily loads that extension's option declarations and dependencies without
starting services or running its data preparation hook. The internal typed API
also rejects unsupported payload schema versions rather than coercing or
overwriting them.

## Extension data lifecycle

Extensions declare typed groups through `ext_register_options()` and prepare
their data through `ext_prepare_data(session)`. The manager binds every definition
to the extension's manifest identifier, inserts missing defaults, and then calls
the preparation hook in a transaction for that owner. Dependencies prepare and
start first; shutdown attempts all started extensions in reverse order. A failed
startup also receives shutdown so that partial startup can be cleaned up.

Preparation must be idempotent and use the supplied session without committing,
rolling back, or closing it. This release supports options and existing core
data facilities; extension-owned schema registration and DDL are not supported.
See [the extension guide](EXTENSIONS.md) for hook contracts and examples.

Disabling or uninstalling normally preserves data and executes no extension
code. Explicit offline cleanup uses:

```powershell
uv run maintain extensions purge-data example
uv run maintain extensions purge-data example --yes
uv run maintain extensions uninstall example --purge-data --yes
```

Standalone purge requires the extension to be disabled. Combined uninstall
cascades disabling through dependants, purges while code is still installed,
and then removes the target's code. Purge failures leave the code available and
the extension disabled so cleanup can be retried. Only the target's purge hook
runs; its changes, owned options and system-state deletion, and the purge audit
record commit together. Core and built-in data are protected.
Purge hooks must handle already absent data because retrying a failed code
removal invokes cleanup again after the earlier purge committed.

For missing or broken extension code, `purge-data example --options-only --yes`
removes only that owner's options and system states without importing code. It
does not remove other data the extension might have created.

## Backup and downgrade

Version 2 logical backups include every owner's options in the configuration
component; version 1 archives remain readable. Restoring validates generic row
structure without importing owners or interpreting their payload schemas. See
[the backup guide](BACKUPS.md) for restoration and database-copy behavior.

Downgrades crossing the options migration are blocked whenever the table contains
any rows, including disabled or unknown owners. The deployment preflight checks
this before changing releases, and the migration itself also refuses the drop.
There is no automatic conversion back into an older release's TOML format.
