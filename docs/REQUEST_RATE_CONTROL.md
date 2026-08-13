# Request Rate Control

CFMS applies admission and rate controls at distinct boundaries so a traffic
spike cannot create an unbounded number of sockets, streams, or worker threads.
Protocol version 21 adds the request-level `429` and `503` conclusions described
below.

## Control layers

| Boundary | Scope | Response | Purpose |
| --- | --- | --- | --- |
| HTTP WebSocket upgrade | source IP | HTTP `429` with `Retry-After` | Limit repeated connection attempts |
| Accepted WebSocket | process and source IP | close code `1013` | Bound live connection resources |
| Pending logical streams | connection | close code `1013` | Stop stream-creation floods |
| In-flight logical requests | process and connection | conclusion `503` | Bound request worker threads |
| Known request action | source IP and authenticated account | conclusion `429` | Apply sustained-use quotas and action costs |

`429` is a client quota decision. `503` and close code `1013` indicate temporary
server capacity pressure. Clients should wait for `retry_after_seconds` when it
is present and otherwise use capped exponential backoff with jitter. HTTP 429
semantics and `Retry-After` follow [RFC 6585](https://www.rfc-editor.org/rfc/rfc6585.html),
and `1013` is registered as “Try Again Later” in the
[IANA WebSocket registry](https://www.iana.org/assignments/websocket/websocket.xhtml).

Request conclusions have the existing CFMS envelope. A quota denial resembles:

```json
{
  "code": 429,
  "data": {
    "scope": "account",
    "limit": 120,
    "retry_after_seconds": 1
  },
  "message": "Too many requests. Please try again later.",
  "timestamp": 1785560400.0
}
```

Capacity denials use code `503` and include `scope` and
`retry_after_seconds`. A request rejected before worker admission doesn't start
a request thread or invoke an action handler.

## Configuration

Hard admission ceilings are always enforced and are process-local:

```toml
[server.admission_control]
max_connections = 64
max_connections_per_ip = 16
max_inflight_requests = 64
max_inflight_requests_per_connection = 8
max_pending_streams_per_connection = 16
busy_retry_after_seconds = 1
```

Token-bucket quotas can be disabled, observed, or enforced:

```toml
[security.request_rate_control]
mode = "observe" # "disabled", "observe", or "enforce"
connection_capacity = 20
connection_refill_tokens = 60
connection_refill_period_seconds = 60
request_refill_period_seconds = 60
account_capacity = 120
account_refill_tokens = 120
ip_capacity = 600
ip_refill_tokens = 600
state_retention_seconds = 600

[security.request_rate_control.action_costs]
search = 4
upload_document = 8
```

Each handler declares a positive integer `rate_limit_cost`, defaulting to one.
Configuration overrides are checked at startup, including handlers registered by
extensions. An override for an unknown action produces a warning. Costs cannot
exceed either request bucket capacity.

### Default action costs

Built-in handlers use six relative cost tiers. With the default account refill
of 120 tokens per minute, costs 1, 2, 3, 5, 10, and 20 permit approximately
120, 60, 40, 24, 12, and 6 sustained calls per minute respectively. The IP
bucket is five times larger. These are starting points for observation-mode
calibration, not measurements of wall-clock time.

| Cost | Actions |
| ---: | --- |
| 1 | `cancel_2fa_setup`, `get_2fa_status`, `get_user_key`, `server_info`, `shutdown` |
| 2 | `refresh_token`, `validate_2fa`, `list_banned_subnets`, `get_document_access_rules`, `list_revisions`, `get_directory_access_rules`, `unblock_user`, `get_user_info`, `revoke_access`, `upload_user_key`, `delete_user_key`, `set_user_preference_dek`, `list_user_keys` |
| 3 | `diagnostics`, `list_auth_lockouts`, `get_document`, `restore_document`, `rename_document`, `move_document`, `get_document_info`, `set_document_tags`, `get_revision`, `set_current_revision`, `list_directory`, `get_directory_info`, `create_directory`, `rename_directory`, `move_directory`, `list_deleted_items`, `search`, `manage_user_status`, `block_user`, `list_user_blocks`, `list_users`, `get_user_avatar`, `set_user_avatar`, `change_user_groups`, `change_user_permissions`, `list_groups`, `create_group`, `get_group_info`, `change_group_permissions`, `grant_access`, `view_access_entries`, `view_audit_logs`, `sso_oidc_start`, `throw_exception` |
| 5 | `login`, `disable_2fa`, `create_banned_subnet`, `update_banned_subnet`, `delete_banned_subnet`, `create_document`, `upload_document`, `delete_document`, `set_document_rules`, `delete_revision`, `download_file`, `upload_file`, `set_directory_rules`, `create_user`, `delete_user`, `rename_user`, `delete_group`, `rename_group` |
| 10 | `unlock_auth_lockouts`, `purge_document`, `delete_directory`, `restore_directory`, `set_passwd`, `lockdown`, `sso_oidc_callback` |
| 20 | `setup_2fa`, `purge_directory` |

The tiers reflect relative database, cryptographic, file-transfer, external
network, and bulk-operation pressure. Method-specific weighted costs are an
established quota pattern; see the
[Google Cloud Endpoints quota guide](https://docs.cloud.google.com/endpoints/docs/openapi/quotas-overview),
[Azure API Management weighted increment policy](https://learn.microsoft.com/en-us/azure/api-management/rate-limit-by-key-policy),
and [GitHub's read/write point model](https://docs.github.com/en/graphql/overview/rate-limits-and-query-limits-for-the-graphql-api).
[OWASP API4](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/)
recommends tuning endpoint limits to business needs and separately bounding
record counts, payload sizes, and batched work.

Costs are fixed per request because quota accounting happens before payload
schema validation and handler execution. They do not scale with directory
subtree size, array length, or file bytes. Pagination limits, file-task
lifecycle controls, hard admission ceilings, and the document-specific risk
controls remain responsible for those variable dimensions. In particular,
document creation and download risk tokens are independent signals and are not
folded into these transport-wide request costs.

The account and IP buckets are charged together for authenticated requests. An
unauthenticated request charges only its IP bucket. Unknown actions are rejected
before quota accounting, while invalid authenticated credentials are rejected
before an account identity is trusted. Users with the
`bypass_request_rate_limit` permission bypass request token buckets, but never
bypass hard admission ceilings or the connection-attempt bucket.

## Provider and cluster behavior

```toml
[provider]
rate_limit = "memory" # or "redis"
```

The memory provider is thread-safe and bounded, but its counters belong to one
server process. With multiple workers or hosts, effective limits multiply and a
client can move between instances. Use `rate_limit = "redis"` with the `cluster`
optional dependencies when quotas must be shared. Redis evaluates all bucket
charges in one Lua operation, uses Redis server time, and expires inactive state.
This follows Redis guidance that Lua keeps the read/decide/update cycle atomic;
see the [Redis rate-limiter guide](https://redis.io/docs/latest/develop/use-cases/rate-limiter/).

If the shared rate-limit provider fails, request quotas fail open so a Redis
outage doesn't become a total service outage. Process-local connection, stream,
and concurrency ceilings remain active. Provider failures and would-block
decisions are rate-limited in logs.

Bucket identities are HMAC-SHA256 digests keyed by `server.secret_key`; raw
account names and IP addresses aren't placed in provider keys. Changing the
secret invalidates existing bucket state. Ensure `trusted_proxy_networks` lists
only proxies that sanitize forwarding headers, because the resolved client IP is
used for both admission and quota scopes.

## Rollout and rollback

1. Deploy with `mode = "observe"` and inspect `request_rate_control` warning
   events for at least one representative peak period.
2. Adjust capacities, refill rates, and expensive action costs. Keep hard
   admission ceilings aligned with database and file-storage capacity.
3. For a cluster, enable and verify Redis before switching to `mode = "enforce"`.
4. Grant bypass only to narrowly controlled service or emergency accounts.
5. Roll back quota enforcement immediately with `mode = "observe"` or
   `"disabled"`; hard safety ceilings intentionally remain enabled.

All settings are read dynamically for decisions, but changing provider type or
handler registrations requires a restart. Lowering a capacity doesn't delete
existing provider state; subsequent decisions clamp stored tokens to the new
capacity.
