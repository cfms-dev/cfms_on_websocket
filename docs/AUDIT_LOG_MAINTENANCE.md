# Audit log maintenance

The maintenance CLI can inspect, export, and manually purge old rows from the
`audit_entries` table. It does not change the WebSocket audit API, run a
background cleanup worker, or delete other operational state.

## Retention policy

When `--before` is omitted, audit commands use this configuration:

```toml
[maintenance.audit_retention]
retention_days = 365
batch_size = 500
```

`retention_days` determines the default cutoff. `batch_size` limits both export
fetching and the number of archived IDs deleted in one transaction. Both values
must be positive integers.

An explicit `--before` value must be an ISO 8601 timestamp with a timezone, for
example `2026-01-01T00:00:00Z` or `2026-01-01T08:00:00+08:00`. Only entries with
`logged_time` strictly earlier than the cutoff are eligible.

## Workflow

Preview eligible entries without writing or deleting anything:

```console
maintain audit purge --dry-run --before 2026-01-01T00:00:00Z
```

The preview reports the total and counts grouped by action and exact result
code. Audit result values are stored as emitted by handlers; do not assume every
successful operation uses the same value.

Export an important subset for separate review:

```console
maintain audit export important.jsonl \
  --before 2026-01-01T00:00:00Z \
  --action lockdown \
  --action block_user \
  --result 403
```

Archive and then purge all entries before the cutoff:

```console
maintain audit purge \
  --archive audit-before-2026.jsonl \
  --before 2026-01-01T00:00:00Z \
  --yes
```

Without `--yes`, the purge asks for confirmation. A non-dry-run purge always
requires `--archive`; the final archive path must not already exist.

## Filters and archive behavior

The `export` and `purge` commands accept repeatable `--action`, `--username`,
`--target`, `--result`, and `--remote-address` filters. Values within one field
are combined with OR, while different fields are combined with AND.

JSONL rows are ordered by `logged_time` and then `id`. Every row contains the
stored `id`, `action`, `username`, `target`, `data`, `result`, `remote_address`,
and `logged_time` values. The export is readable and may expose usernames, IP
addresses, targets, and operation details; store it as sensitive data.

The CLI writes and synchronizes a temporary file in the destination directory
before atomically publishing the final archive without overwriting an existing
path. A purge deletes only IDs read back from that completed archive and applies
the original cutoff and filters again. If the candidate count changes after
confirmation, the CLI keeps the new archive but deletes nothing and asks the
administrator to preview again. If a later deletion batch fails, earlier batches
can remain committed, but the complete archive is retained and the CLI reports
the number already removed.

Audit JSONL files are external records, not CFMS backup archives. The backup
import command cannot restore them automatically.
