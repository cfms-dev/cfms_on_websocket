# Server Extensions

Each extension lives in its own directory under `src/include/extensions` and must
contain both an `_extension.py` entrypoint and a `manifest.toml` file. The
manifest lets the server validate and describe extensions without importing their
Python code.

## Manifest format

Manifest version 1 uses these fields:

```toml
manifest_version = 1
identifier = "example_extension"
name = "Example Extension"
version = "1.0.0"
authors = ["Example Author"]
license = "Apache-2.0"
description = "An optional short description."
homepage = "https://example.com/extensions/example"
```

`manifest_version`, `identifier`, `name`, `version`, `authors`, and `license` are
required. `description` and `homepage` are optional. Unknown fields are rejected.
Use semantic versions for `version` and an SPDX license identifier where possible.

The identifier is the stable configuration and Pluggy registration key. It must
match `^[a-z][a-z0-9_]*$`, must be unique across the installed extension catalog,
and must not change when the extension directory or display name changes.

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

Startup fails when the extension catalog is invalid, an enabled identifier is not
installed, or an enabled extension cannot be imported. This prevents the server
from silently running without configured capabilities.

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
