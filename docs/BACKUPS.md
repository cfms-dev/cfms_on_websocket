# Logical backups and database options

New logical backups use format version 2. Imports accept versions 1 and 2;
older server releases cannot import version 2 archives. The encrypted archive
layout remains unchanged, and the authenticated header and payload versions must
match.

The `configuration` component contains the complete `options` table in addition
to `security.pepper` and `server.secret_key`. Full backups include this component.
Options belonging to disabled, removed, or currently unknown extensions are
preserved with their payload schema versions and concurrency revisions. Restoring
them does not import extension code or run extension initialization. A version 2
configuration backup must declare the options table, even when it contains no
rows. Other selected components cannot include it.

Version 1 backups do not normally contain database options. Restoring an old
backup, importing components without configuration, or restoring an empty options
table establishes the core server defaults. It does not import legacy
`server.name` or `extensions.brute_force_lockdown` settings from the target TOML.
Those legacy keys remain in the file and must be explicitly migrated or discarded
before starting the server. Brute-force lockdown defaults are initialized only
when that extension is enabled.

A restore requires an empty target database, including its options table. Default
options are inserted after archive validation, in the same transaction as the
restored data. Existing restored core options are retained without applying
defaults over them. Successful restoration records the current core Alembic
revision; a database or finalization failure rolls back option rows and that
revision. The empty Alembic version table may remain after a failed restore.

Database engine migration also copies every options row. Runtime state such as
`system_states`, throttling counters, and scheduling execution state remains
excluded from logical backups and must be reconstructible. Extensions cannot
register their own database tables through the options lifecycle.
