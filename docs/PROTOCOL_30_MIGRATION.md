# Protocol 30: username and nickname updates

Protocol 30 adds username changes and separates them from nickname updates.
Upgrade clients and servers together; the removed action has no compatibility alias.
The application release version is unchanged.

## Actions and permissions

| Action | Request data | Ordinary permission | Super permission | Token purpose |
| --- | --- | --- | --- | --- |
| `core.user.username.set` | Required `user_id` and `username` | `set_username` | `super_set_username` | `ESCALATION` |
| `core.user.nickname.set` | Required `user_id`; optional `nickname` | `set_nickname` | `super_set_nickname` | `GENERAL` |

Ordinary permissions allow changing only the caller's account. Super permissions
allow changing any account, including the caller's, without the ordinary permission.
Username and nickname permissions are independent. An elevated token does not
replace the required business permission.

Replace all client calls to `core.user.rename` with `core.user.nickname.set`.
The old action returns `400`. Nickname handling is unchanged: an omitted or null
`nickname` clears it, and an empty string remains an empty string. Its existing
status codes, including `400` for a missing target account, remain unchanged.

## Changing a username

Exchange the login token for one containing `ESCALATION` through the existing
authentication flow, then send an authenticated request with a fresh nonce and
timestamp:

```json
{
  "action": "core.user.username.set",
  "data": {
    "user_id": "aabbccdd-0000-4000-8000-000000000001",
    "username": "alice_updated"
  }
}
```

`user_id` is a UUID selector; equivalent UUID spellings select the same account.
`username` follows the existing creation rules: a string of 1–64 characters,
without trimming, case normalization, or additional character restrictions.
Database collation and uniqueness rules remain the same as account creation.
Other data fields are rejected.

| Result | Code |
| --- | --- |
| Updated successfully, including submitting the current username | `200`, with `data: {}` |
| Invalid request or username already occupied | `400` |
| Missing or invalid authentication | `401` |
| Token lacks `ESCALATION`, or business permission is missing | `403` |
| Authorized target account does not exist | `404` |

Business authorization precedes target lookup. Concurrent requests cannot assign
the same username to different accounts: the database constraint selects the
winner, and a uniqueness conflict returns `400` without changing the losing account.
Other database failures retain the existing server error handling.

Changes preserve the account UUID, nickname, credentials, signing key, and existing
tokens. Future username-based login uses the new name; the old name can be reused
by another account. Clients should refresh their locally stored account name.
OIDC identities remain bound by issuer, subject, and account UUID.

Both actions have request rate cost `5`. Audit targets and actor identifiers remain
UUIDs. Username updates record the original `data.target_username` and requested
`data.new_username`; historical audit rows are not rewritten.

## Database upgrade and default grants

Stop the server and back up its database before running:

```console
uv run --locked maintain database upgrade
```

Revision `03197fed3401` renames `rename_user` to `set_nickname` and
`super_rename_user` to `super_set_nickname` in direct user and group permission
records. It preserves IDs, grants, revocations, validity windows, and duplicates.
Downgrading reverses these names. No schema, account, credential, membership, or
audit changes are required.

Fresh installations grant `set_username` to `user`, and both `set_username` and
`super_set_username` to `sysop`. Existing `sysop` nickname defaults use the renamed
permissions; `user` receives no new nickname permission.

The migration does not add username grants to existing databases. Administrators
can preview and apply the new defaults using the
[existing synchronization command](IDENTITY_PERMISSIONS_API.md#restoring-default-group-permission-records):

```console
uv run --locked maintain permission sync-defaults --dry-run
uv run --locked maintain permission sync-defaults --group user --group sysop --yes
```

Stop every server sharing the database before applying synchronization. Existing
permission records, including revocations and validity windows, are preserved;
missing groups are not recreated.
