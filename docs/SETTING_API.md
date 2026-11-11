# Setting API

Settings are explicitly exposed options, identified by `(namespace, option_key)`.
They share the option's type, default, schema version and concurrency revision.
Core business options and the bundled OIDC and brute-force-lockdown options have
metadata. Deployment configuration, transient state, unregistered stored rows and
options without metadata are not exposed.

All actions require authentication with the usual general-purpose token.
`view_settings` permits discovery and reading; `manage_settings` permits writing.
Neither implies the other. The default `sysop` receives both. Existing deployments
must run `uv run maintain database upgrade` before starting the updated server.

## Discovery

`core.setting.list` accepts `{}` or an exact `namespace` filter. It returns
`{"items": [...]}`, sorted by namespace and option key. Each item contains:

```json
{
  "namespace": "server",
  "option_key": "name",
  "owner": "core",
  "schema_version": 1,
  "title": "Server name",
  "description": "Display name returned by the server information API. Applies to subsequent operations.",
  "default": "CFMS WebSocket Server",
  "value_schema": {"type": "string"}
}
```

`value_schema` comes from the existing annotation using Pydantic's validation
JSON Schema, including representable enums, bounds and member types. Cross-field
relationships and custom validators remain authoritative on the server and are
explained in descriptions. Metadata does not prescribe UI controls or layout.

Discovery reads no option or system-state rows; permissions and existing request
audit still use the database. Unmatched filters return an empty list. Filtering
`server` does not include `server.child`. There is no pagination or values cache.

## Reading actual values

`core.setting.get` accepts a namespace and optional nonempty, unique `keys`.
Omitting `keys` reads all exposed settings in that namespace.

```json
{
  "action": "core.setting.get",
  "data": {"namespace": "security.password", "keys": ["passwd_min_length", "passwd_max_length"]}
}
```

Response data:

```json
{
  "namespace": "security.password",
  "settings": {
    "passwd_min_length": {"value": 8, "revision": 1, "updated_at": 1794400000.0},
    "passwd_max_length": {"value": 32, "revision": 1, "updated_at": 1794400000.0}
  }
}
```

Values are decoded and validated, not raw storage strings. Missing rows resolve
to code defaults with revision `0` and update time `null`, without creating rows.
Times are Unix epoch seconds. One option SELECT fetches the selected batch. Any
unknown or unexposed key rejects the entire request with `404`; a namespace
without exposed settings also returns `404`.

## Atomic updates

`core.setting.update` accepts one namespace and a nonempty changes mapping:

```json
{
  "action": "core.setting.update",
  "data": {
    "namespace": "security.password",
    "changes": {
      "passwd_min_length": {"value": 40, "expected_revision": 1},
      "passwd_max_length": {"value": 64, "expected_revision": 1}
    }
  }
}
```

The response uses the read response shape, containing only submitted keys with
committed values, incremented revisions and update times. Revision `0` creates a
missing row. Writing an equal value still advances its revision. To restore a
default, submit the metadata's default with the current revision.

One setting is the smallest update unit: maps such as `action_costs` and arrays
such as `passwd_rules` are replaced in full. Internal-path patches and batches
spanning namespaces are unsupported. The server validates the complete resulting
namespace, including unexposed options, while preserving unmentioned values and
revisions. Related settings can therefore change together.

Per-option revisions and the existing namespace guard in `system_states` prevent
stale overwrites and competing changes to different keys from bypassing aggregate
validation. Failures roll back the entire batch, guard and option audit. Reread
the relevant settings before retrying a conflict with fresh revisions.

Existing effective-time behavior remains: subsequent operations read current
values, persisted upload deadlines remain unchanged, password policy changes
invalidate pending assessments, and cleanup intervals are reconciled by the
scheduling loop. Individual descriptions explain these qualifications.

## Errors and audit

| Code | Structured data | Meaning |
| --- | --- | --- |
| `400` | `errors` containing field `loc` and `type` | Invalid request shape or revision |

Stored configuration errors and unexpected failures use the existing server error
boundary. Clients must not match message text. Empty write batches, empty or
duplicate read keys, and unknown request fields are rejected.

Transactional option audits use source `setting_api`. The usual request audit
records the authenticated user, namespace, submitted keys and previous/new
revisions. Discovery audits record counts; read audits record key revisions.
Neither audit includes values or defaults.

## Extension declarations

```python
from include.config.options import OptionDefinition, SettingMetadata
from include.extensions.manager import hookimpl

LIMIT = OptionDefinition(
    "limit",
    1,
    int,
    10,
    setting=SettingMetadata(
        "Operation limit",
        "Maximum operations per batch. Applies to subsequent operations.",
    ),
)


@hookimpl
def ext_register_options() -> dict[str, tuple["OptionDefinition[int]", ...]]:
    return {"example.policy": (LIMIT,)}
```

Titles and descriptions must be nonblank. Describe units, effective time and
related constraints. Metadata does not replace the type or `ext_validate_options`.
Existing declarations without metadata remain compatible. There is no additional
registry or Hook: loading exposes the declaration; unloading or failed
registration removes it. Stored values remain preserved while declarations are
absent. Offline options maintenance retains its ability to inspect those rows.
