# Server Diagnostics API

The `diagnostics` action returns a static snapshot for troubleshooting without
probing the database, Redis, S3, or other external services. It requires an
authenticated request with the `diagnostics` permission and uses a
request-rate cost of 3.

The action is not available through the lockdown allowlist. During lockdown,
the caller must also have `bypass_lockdown`; otherwise the normal `999` lockdown
response is returned before the diagnostics permission check.

## Request

```json
{
  "action": "diagnostics",
  "username": "admin",
  "token": "<token>",
  "nonce": "<unique nonce>",
  "timestamp": 1786600000,
  "data": {}
}
```

## Response data

```json
{
  "schema_version": 1,
  "server": {
    "server_name": "CFMS WebSocket Server",
    "core_version": "0.5.0.260812_alpha",
    "protocol_version": 22,
    "debug_configured": false
  },
  "runtime": {
    "python_implementation": "CPython",
    "python_version": "3.14.6",
    "openssl_version": "OpenSSL 3.5.7 9 Jun 2026",
    "operating_system": "Windows",
    "operating_system_release": "11",
    "architecture": "AMD64"
  },
  "component_versions": {
    "cryptography": "50.0.0",
    "orjson": "3.11.9",
    "pluggy": "1.6.0",
    "pydantic": "2.13.4",
    "sqlalchemy": "2.0.51",
    "websockets": "17.0.1"
  },
  "database": {"dialect": "sqlite", "driver": "pysqlite"},
  "providers": {
    "storage": "local",
    "caching": "memory",
    "event_bus": "local",
    "rate_limit": "memory"
  },
  "extensions": [
    {"identifier": "builtin", "name": "CFMS Built-in Extension", "version": "0.5.0"}
  ],
  "extension_flags": [],
  "lockdown": {"enabled": false, "reason": null}
}
```

Component versions are limited to the core allowlist. Redis, Boto3, or the
MySQL connector is added only when its corresponding backend is configured.
Extension entries describe modules that completed registration, in load order.

The response never includes filesystem paths, hostnames, IP addresses, ports,
database URLs or names, Redis or S3 endpoints, bucket names, credentials,
secrets, keys, certificates, environment variables, process identifiers, logs,
exception traces, user data, or a complete installed-package inventory.

Successful and denied calls are audited, but the diagnostic snapshot itself is
not copied into the audit entry.
