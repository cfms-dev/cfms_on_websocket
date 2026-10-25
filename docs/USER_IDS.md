# Account identity

`User.id` is a generated UUID v4 and the user table's primary key. The UUID is
immutable for the account's lifetime. Deleting an account and creating another
with the same username produces a different UUID.

JWT `sub` contains the account UUID as a string. WebSocket and HTTP authentication
look up that UUID and verify the signature with the account's current signing
key. Username claims and malformed subjects cannot authenticate. Renaming an
account does not transfer or invalidate its identity; deleting it invalidates
its tokens even when the replacement uses the same signing key.

Login credentials, OIDC username claims and password authentication throttles
still use usernames. Authentication failures may target names that have never existed.
Audit `target` preserves that name, while the authenticated actor is stored in
`user_id`. A refresh operation likewise records the account's username as its
target and its UUID as the actor.

Authenticated request envelopes require a token, nonce and timestamp. The
server derives the identity from the verified token; a supplied envelope
username does not select or override the account. Login responses and user
information include `user_id` as a UUID string.

A password login submits `data.method = "password"` and
`data.credential = {"username": "alice", "password": "..."}`. If the response
is `202`, its `data.token` is an `AUTH` token and `data.methods` lists the
available second factors. Submit that token to `exchange_token` with
`data = {"method": "totp", "data": {"token": "123456"}, "target_purpose": 2}`,
a fresh nonce and timestamp. A successful response supplies the general session
token.

Credentials, permissions, group memberships, keyring ownership, blocks, document
metadata, download task attribution and scheduling attribution reference UUIDs.
Direct user access grants store the UUID string in `entity_identifier`; group
identifiers retain their group names. User grant requests supply that UUID
directly. Document metadata returns UUID
strings in `creator` and `last_modified_by`. HTTP extensions use
`HttpPrincipal.user_id` for audit attribution and account rate limits.

## Protocol 28 user management

Protocol 28 makes user management selectors UUID-based. Discover an account with
`list_users` or `get_user_info`, then use its `user_id` for subsequent operations.
Login responses and successful `create_user` responses also supply `user_id`;
the creation response includes `username` as well.

`get_user_info` requires exactly one of `username` and `user_id`. Fields determine
their meaning: a UUID-shaped username supplied as `username` is still a username.
An omitted selector, both selectors, null values, invalid UUIDs, and unknown
fields return `400`. Reading another account still requires `get_user_info`.

For example, submit these authenticated action/data pairs with the usual token,
fresh nonce, and timestamp on each request:

```json
{"action": "get_user_info", "data": {"username": "alice"}}
```

After reading `response.data.user_id`, use that UUID:

```json
{
  "action": "change_user_permissions",
  "data": {
    "user_id": "aabbccdd-0000-4000-8000-000000000001",
    "permissions": []
  }
}
```

| Actions | Account selector |
| --- | --- |
| `delete_user`, `rename_user`, `block_user`, `list_user_blocks` | Required `user_id` |
| `get_user_avatar`, `set_user_avatar`, `change_user_groups`, `change_user_permissions`, `manage_user_status` | Required `user_id` |
| `disable_2fa`, `get_2fa_status`, `upload_user_key`, `list_user_keys` | Optional `user_id`; omitted means the authenticated account |
| `grant_access` with `entity_type = "user"` | User UUID in `entity_identifier` |
| `view_access_entries` with `object_type = "user"` | User UUID in `object_identifier` |

`rename_user` changes only the nickname. `manage_user_status` returns `user_id`,
`username`, `status`, and `reason`. Block creation, update, and listing include
the owner's `user_id`. `unblock_user` and `update_user_block` keep `block_id`;
key-specific actions keep their key ID; `revoke_access` keeps `entry_id`.

`set_passwd` accepts `new_passwd` and optional `user_id` (default: caller).
Ordinary requests require a GENERAL|ESCALATION token and
`configure_auth_methods` for oneself or `super_configure_auth_methods` for any
account. The super permission also gates `bypass_passwd_requirements` and
`force_update_after_login`. The removed `username` and `old_passwd` fields return
`400`; no old password is required. A restricted POST_AUTH token can still
complete its subject's mandatory password change using only `new_passwd`, without
configuration permission or elevation.

Disabling one's own 2FA still requires the current password and a configuration
permission. Disabling another account's 2FA requires
`super_configure_auth_methods` and must not include a password. Reading another
account's 2FA status requires `super_list_user_auth_methods`.

User management audit `target` contains the canonical UUID and `user_id` contains
the actor UUID. Once the target is authorized and resolved,
`data.target_username` records its name at the time. Resource operations retain
their resource ID target and can include `data.target_user_id` for the owner.
Credential authentication events retain username targets. Existing audit rows
are not rewritten.

User block and access-entry cursors bind the canonical account UUID. Equivalent
UUID spellings select the same account; a cursor cannot be reused for another
account. Missing users retain empty block/access-entry listings.

Upgrade clients and servers together from protocol 27 to 28. Old `username`,
`target`, and `target_username` management selectors are rejected rather than
accepted through a compatibility path. Restart affected pagination after the
upgrade. This protocol change requires no database migration or token replacement.
Local maintenance CLI selectors, login credentials, OIDC username claims, and
authentication-lockout selectors retain their existing username semantics.

## Historical UUID database upgrade

Stop the server and back up its database before running
`uv run maintain database upgrade`. Revision `d252e662fc05` assigns UUIDs to
existing accounts and translates their references. It preserves password hashes,
TOTP secrets and audit targets. Orphaned required references abort the upgrade;
nullable references to deleted users become null. Direct user grants whose
target no longer exists are removed. Short-lived account risk counters are reset;
IP counters and username authentication throttles are retained.

Existing username-based tokens must be replaced by logging in again. Downgrading
restores username references and discards UUIDs; a subsequent upgrade assigns new
UUIDs. Backups preserve UUID values and restore them as native UUID columns.
