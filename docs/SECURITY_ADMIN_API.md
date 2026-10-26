# Security administration API

These authenticated WebSocket actions manage CIDR blocks and active authentication
lockouts. All times are Unix epoch seconds encoded as JSON numbers.

## Permissions

| Permission | Actions |
| --- | --- |
| `list_banned_subnets` | `core.security.banned_subnet.list` |
| `manage_banned_subnets` | `core.security.banned_subnet.create`, `core.security.banned_subnet.update`, `core.security.banned_subnet.delete` |
| `list_auth_lockouts` | `core.security.auth_lockout.list` |
| `unlock_auth_lockouts` | `core.security.auth_lockout.unlock` |

The default `sysop` group receives all four permissions.

## CIDR rules

`core.security.banned_subnet.list` accepts `page_size`, `cursor`, and an optional `status` of
`scheduled`, `active`, or `expired`. It returns the standard cursor response; each
item contains `subnet`, `reason`, `created_at`, `starts_at`, `expires_at`, and
`status`.

Create a rule with:

```json
{
  "action": "core.security.banned_subnet.create",
  "data": {
    "subnet": "192.0.2.7/24",
    "reason": "Incident response",
    "starts_at": 1784894400.0,
    "expires_at": 1784980800.0
  }
}
```

The server canonicalizes the example to `192.0.2.0/24`. `starts_at` defaults to
the current time and `expires_at` defaults to `null`. The interval is
`[starts_at, expires_at)`. Creating or updating a non-expired rule containing the
requester's effective IP requires `"confirm_self_block": true`.

`reason` follows the shared 1-to-1024-character operation-reason contract.
`core.security.banned_subnet.update` identifies the rule by `subnet` and accepts any of
`reason`, `starts_at`, or `expires_at`; omitted values remain unchanged and an
explicit `null` clears the reason. A reason-only update does not refresh the
active subnet guard. To change the CIDR itself, delete the old rule and create a
new one. `core.security.banned_subnet.delete` accepts only `subnet`. See
[`OPERATION_REASONS.md`](OPERATION_REASONS.md) for the shared update and audit
semantics.

## Authentication lockouts

`core.security.auth_lockout.list` accepts cursor pagination and optional exact filters:
`scope`, `username`, `ip_address`, and `factor`. It returns active lockouts sorted
by expiration time. Scope-specific identifiers are:

- `ip`: `ip_address`
- `account`: `username` and `factor`
- `account_ip`: `username` and `ip_address`

Every item also includes `failed_attempts`, `window_started_at` (null for account
scope), `last_attempt`, `locked_until`, and `retry_after_seconds`.

Clear up to 100 exact lockouts in one transaction:

```json
{
  "action": "core.security.auth_lockout.unlock",
  "data": {
    "reason": "Approved emergency access",
    "locks": [
      {"scope": "account", "username": "alice", "factor": "password"},
      {"scope": "account_ip", "username": "alice", "ip_address": "192.0.2.10"}
    ]
  }
}
```

The response contains `cleared` and `not_found` selector arrays. The operation is
idempotent and resets the selected failure histories. If an access attempt is
blocked by multiple scopes, every matching scope must be cleared. The supplied
reason and results are recorded in the audit log.
