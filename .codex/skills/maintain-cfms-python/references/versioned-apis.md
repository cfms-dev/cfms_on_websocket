# Versioned API guidance

## Contents

- Resolve the actual API
- SQLAlchemy
- websockets
- Pluggy
- uv and Ruff
- Other project dependencies
- Primary sources

## Resolve the actual API

Never equate a lower bound in `pyproject.toml` with the installed version. At the time of authoring, the lock/environment included SQLAlchemy 2.0.51, websockets 16.0, Pluggy 1.6.0, pytest 9.1.1, jsonschema 4.26.0, and Typer 0.26.8. Re-check `uv.lock` and query installed metadata before every version-sensitive change:

```powershell
uv run python -c "from importlib.metadata import version; print(version('websockets'))"
uv lock --check
```

Use `uv run --locked ...` when validation must not update the lockfile. Do not edit `uv.lock` by hand. Upgrade one package intentionally with `uv lock --upgrade-package <name>` only when the task authorizes dependency changes, then review the entire resolution diff.

## SQLAlchemy 2

Prefer documented SQLAlchemy 2 forms:

- `session.get(Model, key)` for identity lookup;
- `select(...)` with `session.execute()` / `session.scalars()`;
- `scalar_one()`, `scalar_one_or_none()`, or `scalars().all()` according to cardinality;
- explicit `update()` / `delete()` and checked `rowcount` for conditional state transitions;
- context-managed sessions and explicit transaction ownership.

`Session.query()` remains available but is a long-term legacy API and is no longer the primary documentation path. Do not add new uses. Do not mass-rewrite test-only `session.query()` calls unless the task includes that cleanup; keep behavioral changes and mechanical migrations separate.

Understand result semantics before migration: `first()` no longer adds `LIMIT 1` automatically, joined eager loads may require `unique()`, and `Session.execute()` returns `Result` rows unless `scalars()` is selected. A syntactic conversion without these checks can silently change performance or shape.

Do not hide commits inside helpers accepting a caller-owned `Session`. Use database constraints or conditional DML for races; application prechecks alone are insufficient.

## websockets 16

CFMS intentionally uses the threading implementation under `websockets.sync.server` and `websockets.sync.client`. Keep imports on documented `sync` paths and type against `Server`, `ServerConnection`, and corresponding sync classes.

Do not apply the asyncio migration guide to sync code mechanically. Do not import from `websockets.legacy`, `websockets.server`, or convenience aliases when a stable `websockets.sync.*` path exists. Verify connection lifecycle and exception behavior in the 16.0 sync reference.

The sync `serve()` result is a context manager and mirrors `socketserver.BaseServer`. Preserve ownership of close/`serve_forever()`. Handle `ConnectionClosed` subclasses around actual send/receive operations rather than probing removed/discouraged `open` or `closed` properties.

When upgrading, first expose warnings, then read the changelog/reference for both the old locked and proposed versions. Preserve buffer, timeout, handshake, TLS, and subprotocol semantics; matching names do not guarantee matching defaults.

## Pluggy 1.6

Hook specifications define callable names and argument names. Implementations may omit unused hook arguments, but must not invent unsupported ones. Reuse existing markers, manager, hook order, and `firstresult` semantics.

Python 3.14 caveat: Pluggy calls `inspect.signature()` while registering specs/implementations. This evaluates deferred annotations and raises `NameError` for a type imported only under `TYPE_CHECKING`. Keep those hook annotations as explicit strings. Verify both registration and hook invocation when modifying a signature.

Do not add a hook for one core caller unless optional extensions genuinely need a stable lifecycle point. Define precise timing, transaction ownership, error propagation, idempotence, and response visibility before adding any hook.

## uv and Ruff

Use `uv` for environment-dependent commands and dependency changes. `uv run` can update the lockfile/environment automatically; use `--locked` when an inspection or test must be read-only with respect to resolution. Use `uv lock --check` to verify consistency.

Ruff configuration selects import sorting and pyupgrade (`I`, `UP`) and contains deliberate per-file exceptions for ORM forward references, Pluggy annotations, tests, migrations, and certificate tools. Do not delete an ignore as “obsolete” without verifying the runtime/tool reason. Never invoke Ruff directly in this repository; use pre-commit as required by `AGENTS.md` and review automatic edits.

## Other project dependencies

- Use `importlib.metadata.version()` when package version attributes are undocumented. `jsonschema.__version__`, for example, emits a deprecation warning in the locked environment.
- Use `jsonschema` at untrusted request/config boundaries. Do not repeat identical field validation deep in already validated domain code.
- Use Typer's public `Annotated` command/option interfaces and the exact installed docs for CLI changes; avoid falling back to deprecated `argparse.FileType` patterns.
- Keep provider-specific dependencies inside their optional feature/import boundary. Core startup must not require Redis, S3, MySQL, or OIDC packages when the feature is disabled.
- Treat cryptographic APIs and formats as versioned security contracts. Never substitute algorithms, nonce/key sizes, encodings, or verification order based on memory; read the exact official docs and existing migration/data format.

## Primary sources

- [SQLAlchemy 2.0 migration guide](https://docs.sqlalchemy.org/en/20/changelog/migration_20.html)
- [SQLAlchemy session transactions](https://docs.sqlalchemy.org/en/20/orm/session_transaction.html)
- [websockets 16 sync server reference](https://websockets.readthedocs.io/en/16.0/reference/sync/server.html)
- [websockets upgrade guide](https://websockets.readthedocs.io/en/16.0/howto/upgrade.html)
- [Pluggy documentation](https://pluggy.readthedocs.io/en/stable/)
- [uv locking and syncing](https://docs.astral.sh/uv/concepts/projects/sync/)
- [Ruff rules](https://docs.astral.sh/ruff/rules/)
