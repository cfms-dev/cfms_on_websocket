# Database configuration

Business settings are stored as individual `(namespace, option_key)` entries.
`owner` records the declaring core or extension identifier for maintenance and
explicit data cleanup; it does not determine the namespace. Extensions may
manage several namespaces. A namespace normally has one declaring party by
convention. Duplicate setting identities are rejected.

Each row includes an owner, schema version, positive concurrency revision, type,
text value and update timestamp. Strings are stored verbatim; other scalar types
use tagged text; only objects and lists use JSON. Namespaces use lowercase ASCII
snake_case segments separated by dots, with a maximum of 111 characters. Missing
rows resolve to code defaults with revision zero. Unsupported stored schemas and
invalid values fail explicitly rather than silently falling back.

## Settings and effective time

| Namespace | Settings |
| --- | --- |
| `server` | `name` |
| `security.password` | Password lengths, rules, required rule count and expiration |
| `security.auth_throttle` | Authentication throttling and record retention |
| `security.request_rate_control` | Request and connection rate policy, including the JSON `action_costs` map |
| `security.brute_force_lockdown` | The detector's five policy fields |
| `access` | `enable_access_recursive_check` |
| `document.upload` | Upload timeouts, cleanup interval and pending-document limit |
| `document.upload.creation_risk_control` | Document creation risk policy |
| `document.download.risk_control` | Document download risk policy |
| `identity.permission_retention` | Permission cleanup policy |
| `maintenance.audit_retention` | Audit maintenance defaults |
| `scheduling` | `misfire_grace_seconds` and `history_retention_days` |
| `identity.oidc` | `username_claim`, `auto_provision` and `default_groups` |

Policies are read from the database for each operation, with a snapshot reused
within that operation. No process-wide options cache or refresh thread is used.
An existing upload task's persisted deadline is not rewritten. Password assessment
and its digest use the same policy; changing the policy invalidates an assessment
that is awaiting completion of authentication. Cleanup intervals are reconciled
by the existing scheduling provider loop, and execution reads the latest policy.

`config.toml` contains deployment settings: database and provider connections,
secrets, networking, TLS paths and reload parameters, transport chunk sizes,
process resource ceilings, scheduling workers and leases, extension activation,
and HTTP API startup settings. OIDC issuer, client credentials, callback URI,
scope and state lifetime also remain there. All TOML changes require a restart;
the file is not watched. Certificate/key content reload remains supported by
WSS and HTTP API, and still uses `watchdog`.

## Upgrade an existing deployment

Stop every server node and exclude other maintenance writers before upgrading.
The server directory runtime lock is local, not a cluster maintenance lock.

```powershell
uv run maintain database upgrade
uv run maintain config migrate-options --check
uv run maintain config migrate-options --yes
uv run maintain config sync-template
```

The preview validates all legacy business settings, including disabled extension
policies. Existing compatible legacy password/rate/OIDC conversions are applied
before importing their replacement settings. Warnings report obsolete settings,
including the unused `require_passwd_enforcement_changes`; that flag is removed
without introducing a new behavior.

Migration inserts missing settings and then removes migrated fields from TOML
using the existing atomic backup/write mechanism. Equal rows keep their revisions
and do not generate duplicate audit entries. Conflicting values require explicit
`--discard-legacy --yes`, which keeps database values or validated code defaults.
Database changes commit before TOML cleanup. If cleanup fails, rerun the command
to complete it safely. Startup refuses outstanding legacy business fields without
importing them automatically. Template synchronization cannot discard these
values or reintroduce database-backed settings.

Fresh databases are initialized and stamped. Existing databases must be explicitly
upgraded to this release's Alembic head before startup. The unreleased feature
branch's earlier database and version 2 backup shapes are not migration targets;
rebuild those development databases.

## Read and update settings

```powershell
uv run maintain config options list
uv run maintain config options list --namespace security.password
uv run maintain config options get server name
uv run maintain config options set server name server-name.json --expected-revision 1
uv run maintain config options reset server name --expected-revision 2
uv run maintain config options set-many security.brute_force_lockdown changes.json
```

A single-setting JSON file contains the value, for example `"My CFMS Server"`.
`set-many` accepts a mapping of setting keys to `value` and `expected_revision`:

```json
{
  "failure_threshold": {"value": 5, "expected_revision": 1},
  "distinct_account_threshold": {"value": 5, "expected_revision": 1},
  "distinct_ip_threshold": {"value": 5, "expected_revision": 1}
}
```

The complete namespace is validated before a batch commits. Unmentioned keys
retain their values and revisions. Stale revisions reject the entire batch;
revision zero creates a missing row. Reset persists the code default and advances
its revision. Writes and audit records share a transaction. Audits record key
names and revisions, not values.

A namespace-wide optimistic guard under
`system_states/core/options_revision.<namespace>` prevents concurrent edits to
different keys from bypassing aggregate validation. Retry conflicts with a fresh
transaction and read. Coordination guards are transient and excluded from logical
backups.

List/get do not import extension code, so stored settings remain inspectable when
an extension is disabled, removed or broken. Core defaults are also visible.
Extension writes locate their declaration through the manifest's optional
`option_namespaces` field, then temporarily load that extension and dependencies
without starting services or preparing data.

## Extension lifecycle and backups

`ext_register_options()` returns definitions grouped by namespace;
`ext_validate_options(namespace, values)` validates a complete normalized policy.
Defaults and `ext_prepare_data(session)` run transactionally before services
start, in dependency order. Disabling/uninstalling normally preserves data.
Explicit offline `extensions purge-data` and `uninstall --purge-data` retain
transactional cleanup and remove only data owned by the target extension.
`--options-only` can recover owned option/state rows without importing broken code.
Core and builtin data remain protected. See [the extension guide](EXTENSIONS.md).

Version 2 logical backups include all option namespaces and ownership metadata;
version 1 archives remain readable. Restore validates generic encoding without
importing plugins or interpreting policy schemas. A missing server name is
established from its code default; other missing options resolve to defaults and
are initialized on startup. Existing extension table backup support is preserved.
Nonempty options block downgrades that would drop the table. There is no automatic
conversion back to TOML. See [the backup guide](BACKUPS.md).
