# Historical authentication fixtures

Generated with the unmodified models and public `export_backup` API at
`3959ce69559c718d758182d3de1b1101e348dfc5` (PR #102's base).
`schema.sql` is SQLite's schema at revision `0460356a5ba6`; `seed.sql`
contains only synthetic data. Load the SQL with foreign keys temporarily
disabled to accommodate the `users`/`keyrings` cycle, then enable and check them.

`backup.conf` is that database's full archive, encrypted with the test key
`b"r" * 32`. Alice's password is `LegacyPassword123!`; its modification marker
is zero and TOTP is enabled. The `pending` account has an empty password hash
and pending TOTP. Both accounts, their credentials, and every key are fictitious.
The fixtures include group membership, permissions, a preference key, audit
history, document attribution, scheduling attribution, and direct user grants.
The grant for `deleted-user` deliberately has no remaining account.

These snapshots are independent of current ORM metadata and migration
downgrades, so a missing historical upgrade cannot redefine the test's input.
