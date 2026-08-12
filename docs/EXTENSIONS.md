# Server Extensions

Each extension lives in its own directory under `src/include/extensions` and must
contain both an `_extension.py` entrypoint and a `manifest.toml` file. The
manifest lets the server validate and describe extensions without importing their
Python code.

## Manifest format

Manifest version 2 separates extension metadata from server compatibility:

```toml
manifest_version = 2

[extension]
identifier = "example_extension"
name = "Example Extension"
version = "1.0.0"
authors = ["Example Author"]
license = "Apache-2.0"
description = "An optional short description."
homepage = "https://example.com/extensions/example"

[compatibility]
minimum_server_version = "0.5.0.260812_alpha"
```

`manifest_version` and the `[extension]` table are required. Within `[extension]`,
`identifier`, `name`, `version`, `authors`, and `license` are required;
`description` and `homepage` are optional. The `[compatibility]` table and
`minimum_server_version` are optional. Omitting the minimum version declares no
server-version floor. Unknown tables and fields are rejected.

Use semantic versions for the extension's own `version` and an SPDX license
identifier where possible. `minimum_server_version` uses the CFMS core version
format reported by `server_info.version`:
`MAJOR.MINOR.PATCH[.BUILD][_TYPE[NUMBER]]`. Supported release types are `alpha`,
`beta`, `rc`, and `release`, ordered from earliest to latest; omitting the type is
equivalent to `release`. Version values must be bare versions without comparison
operators.

Flat manifest version 1 files are no longer supported. Extension developers must
set `manifest_version = 2`, move descriptive fields into `[extension]`, and add
`[compatibility]` when the extension requires a particular server version.

The identifier is the stable configuration and Pluggy registration key. It must
match `^[a-z][a-z0-9_]*$`, contain at most 255 characters, must not be `core`,
must be unique across the installed extension catalog, and must not change when
the extension directory or display name changes. Identifier values are validated
exactly as written and are never trimmed or otherwise normalized.

## Activation

Optional extensions are loaded in the order listed in the server configuration:

```toml
[extensions]
enabled = ["example_extension"]
```

The `builtin` extension provides core server behavior and is always loaded first;
do not list it in `enabled`. Configuration changes require a server restart. The
server validates every installed extension manifest at startup, but imports only
the built-in extension and identifiers listed in `enabled`.

Before importing any extension code, the server checks the complete set of
extensions selected for this load. If the current core version is lower than any
selected extension's `minimum_server_version`, startup fails with the extension
identifier, required version, and current version, and none of the selected
extensions are imported. An installed but disabled extension may target a newer
server without blocking startup, although its manifest must still be valid.

Startup also fails when the extension catalog is invalid, an enabled identifier
is not installed, or an enabled extension cannot be imported. This prevents the
server from silently running without configured capabilities.

Extensions may implement `ext_validate_config(config)` to validate their own
configuration. The hook runs when an extension is loaded and whenever the global
configuration is reloaded. It should raise `ConfigValidationError` for invalid
values; a failed reload leaves the previous configuration active.

## Request handlers

Extensions register request handlers through `ext_register_handlers()`. Every
registered class must inherit `RequestHandler` and define `request_model` as a
`RequestDataModel` subclass. The server validates this contract at startup and
fails fast when an extension still exposes a legacy `schema` dictionary; there
is no JSON Schema fallback for handler request data.

```python
from include.extensions.manager import hookimpl
from include.transport.request_handler import (
    REQUEST_UNSET,
    Omittable,
    RequestDataModel,
    RequestHandler,
    NonEmptyString,
    Result,
)

class EchoRequest(RequestDataModel):
    message: NonEmptyString
    label: Omittable[NonEmptyString] = REQUEST_UNSET


class EchoHandler(RequestHandler):
    request_model = EchoRequest

    def handle(self, handler):
        handler.conclude_request(200, {"message": handler.data["message"]}, "OK")
        return Result(code=200)


@hookimpl
def ext_register_handlers() -> dict[str, type[RequestHandler]]:
    return {"echo": EchoHandler}
```

`RequestDataModel` uses strict Pydantic validation and rejects unknown fields by
default. Use `Omittable[T]` with `REQUEST_UNSET` when a field may be absent but
must reject an explicit JSON `null`; use `T | None` when `null` is valid. After
validation, `ConnectionHandler.data` remains the original JSON dictionary, so
existing handler and hook code may continue to use dictionary operations.

When request data fails validation, the server returns `400` with every safe
Pydantic error under `data.errors`:

```json
{
  "code": 400,
  "data": {
    "errors": [
      {
        "type": "int_type",
        "loc": ["value"],
        "msg": "Input should be a valid integer"
      }
    ]
  },
  "message": "Invalid request data"
}
```

Each error contains only `type`, `loc`, and `msg`. The submitted input,
validation context, and Pydantic documentation URL are omitted. Extension
validators must use static, client-safe error messages and must not interpolate
request values, credentials, or other secrets into validation errors.

Extensions that own background services may implement `ext_on_startup()` and
`ext_on_shutdown()`. Startup runs after the database, providers, and request
handlers are ready. Shutdown runs whenever the serving loop exits, including
startup failures, and implementations must be idempotent. The startup hook may
accept the bound `server` when it needs access to the WebSocket server itself.

Non-empty uploads expose three ordered extension points. The
`ext_before_file_upload_finalize(session, id, path, sha256)` hook runs inside the
upload completion transaction; implementations may add database work through
the supplied session but must not commit or close it. After that transaction
commits, `ext_on_file_uploaded(id, path, sha256)` retains its existing position
before the success response. Finally,
`ext_on_file_upload_completed(id, path, sha256)` runs after the response has
been sent and must not attempt to change the completed client result.

The `builtin` extension uses these hooks together with its startup and shutdown
hooks to own durable file deduplication. Core upload handling publishes the
lifecycle events but does not schedule or run deduplication itself.

## Persistent runtime state

Core features and trusted extensions may use `include.database.system_states`
to persist small, low-frequency runtime state across process restarts. Each
extension uses its manifest identifier as `owner`; `core` is reserved for the
server. State keys are lowercase identifiers that may also contain `.`, `-`,
and `_`.

The state API accepts a caller-owned SQLAlchemy session and never commits,
rolls back, or closes it. Creates are insert-if-absent, while updates and deletes
require the revision returned by `read_system_state`. A failed comparison means
another transaction changed the row and the owner must reread before deciding
whether to retry. Payload schema versions belong to the owner: extensions must
explicitly migrate supported older versions and must not overwrite an unknown
newer version.

Disabling or removing an extension does not delete its rows. Runtime state is
excluded from logical backups and must remain safely reconstructible. Do not
store secrets, configuration, business records, high-frequency counters, large
payloads, task queues, or data that needs field indexes, foreign keys, or
database-level field constraints in this table; use a dedicated model and
migration for those cases.

## Automatic brute-force lockdown

Enable the optional `brute_force_lockdown` extension to escalate a service-wide
burst of failed local password or TOTP checks into the existing lockdown mode:

```toml
[extensions]
enabled = ["brute_force_lockdown"]

[extensions.brute_force_lockdown]
window_seconds = 600
failure_threshold = 50
distinct_account_threshold = 10
distinct_ip_threshold = 10
reason = "Automatic security lockdown: suspected credential-guessing attack detected."
```

The extension counts only HTTP-style `401` results from the built-in `login`
action that target existing accounts. Successful authentication, requests for a
second factor, throttled requests, unknown usernames, and OIDC actions are not
counted. Lockdown begins when the failure threshold is reached and either the
distinct-account or distinct-IP threshold is reached in the same rolling window.

Automatic lockdown never replaces an existing manual lockdown reason and does
not expire automatically. An administrator must disable it through the existing
`lockdown` action. Doing so starts a fresh detection window. The public reason is
generic; aggregate trigger counts and thresholds are recorded under the
`automatic_lockdown` audit action without account or IP lists.

The lockdown status, public reason, and last disable timestamp are stored in the
database. A normal or abnormal server restart therefore restores the previous
locked or unlocked state without replaying transition side effects.

## OIDC migration

OIDC activation is now controlled exclusively by the `oidc_sso` identifier. Remove
the old `sso.oidc.enabled` key, install its optional dependencies, and enable it:

```bash
uv sync --extra ext_oidc_sso
```

```toml
[extensions]
enabled = ["oidc_sso"]

[sso.oidc]
issuer = "https://issuer.example"
client_id = "cfms-client"
client_secret = ""
redirect_uri = "https://client.example/callback"
username_claim = "preferred_username"
auto_provision = false
default_groups = ["user"]
```
