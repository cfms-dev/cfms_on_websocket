# Logical backups and database options

New logical backups use format version 2. Imports accept versions 1 and 2;
older server releases cannot import version 2 archives. The encrypted archive
layout remains unchanged, and the authenticated header and payload versions must
match.

The `configuration` component contains the complete `options` table in addition
to `security.pepper` and `server.secret_key`. Full backups include this component.
Options belonging to disabled, removed, or currently unknown extensions are
preserved with their value types, raw stored text, schema versions, and concurrency
revisions. Restoring them does not import extension code or run extension
initialization. A version 2 configuration backup must declare the options table,
even when it contains no rows. Other selected components cannot include it.

Each option row contains `namespace`, `owner`, `option_key`, `schema_version`, `revision`,
`value_type`, `option_value`, and `updated_at`. The `value_type` distinguishes
`str`, `int`, `float`, `bool`, `null`, and `json`; `option_value` is always text.
Strings are stored verbatim, booleans use `1` or `0`, null uses an empty string,
and only dictionaries and lists use JSON. Imports validate row metadata and this
encoding without applying an owner's current setting schema, so future-schema
options, including core options, retain their exact stored representation.
The former grouped `payload` row shape is rejected; the backup format version
remains 2.

Version 1 backups do not normally contain database options. Restoring an old
backup, importing components without configuration, or restoring an empty options
table establishes the missing `server/name` default. It does not import
legacy `server.name` or `extensions.brute_force_lockdown` settings from the target
TOML. Those legacy keys remain in the file and must be explicitly migrated or
discarded before starting the server. Brute-force lockdown defaults are
initialized only when that extension is enabled.

A restore requires an empty target database, including its options table. Default
options are inserted after archive validation, in the same transaction as the
restored data. An existing restored `server/name` option is retained without
parsing its owner schema or applying defaults over it. Successful restoration
records the current core Alembic revision; a database or finalization failure
rolls back option rows and that revision. The empty Alembic version table may
remain after a failed restore.

Database engine migration also copies every options row. Runtime state such as
`system_states`, including option coordination guards, throttling counters, and
scheduling execution state remains excluded from logical backups and must be
reconstructible. Options preparation does not replace existing extension-owned table declarations
and backup codecs.
