# Account identity

`User.id` is a generated UUID v4 and the user table's primary key. The UUID is
immutable for the account's lifetime. Deleting an account and creating another
with the same username produces a different UUID.

JWT `sub` contains the account UUID as a string. WebSocket and HTTP authentication
look up that UUID and verify the signature with the account's current signing
key. Username claims and malformed subjects cannot authenticate. Renaming an
account does not transfer or invalidate its identity; deleting it invalidates
its tokens even when the replacement uses the same signing key.

Login credentials, administrator target selectors, OIDC username claims and
password authentication throttles still use usernames to locate existing
accounts. Authentication failures may target names that have never existed.
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
available second factors. Submit that token to `complete_mfa` with
`data = {"method": "totp", "data": {"token": "123456"}}`, a fresh nonce and
timestamp. A successful response supplies the general session token.

Credentials, permissions, group memberships, keyring ownership, blocks, document
metadata, download task attribution and scheduling attribution reference UUIDs.
Direct user access grants store the UUID string in `entity_identifier`; group
identifiers retain their group names. A grant request's username selector is
resolved before the durable grant is written. Document metadata returns UUID
strings in `creator` and `last_modified_by`. HTTP extensions use
`HttpPrincipal.user_id` for audit attribution and account rate limits.

## Database upgrade

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
