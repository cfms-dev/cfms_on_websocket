# CFMS project architecture

## Contents

- Repository facts
- Responsibility map
- Existing extension points
- Transaction and concurrency rules
- Abstraction decisions
- Change-specific checks

## Repository facts

Treat these as a repository snapshot, then re-read the live files before acting:

- `pyproject.toml` declares Python `>=3.14`; `.python-version` selects 3.14.
- The package uses a `src/` layout with first-party packages `include` and `maintenance`.
- The server uses the threading API in `websockets.sync`, not an asyncio server architecture.
- SQLAlchemy 2 manages persistence. SQLite is the common local/test engine; MySQL and PostgreSQL are configured alternatives.
- Pluggy owns optional extension hooks. Provider base classes own storage, caching, and event backend variation.
- `orjson` handles protocol serialization; `jsonschema` validates request shapes.
- `uv.lock` is committed and records actual resolved versions. Minimum constraints in `pyproject.toml` are not the installed API version.
- Ruff formatting and linting run through pre-commit. Project policy says not to invoke Ruff directly.
- The project is security-sensitive and stateful. Uploads, access rules, tokens, throttles, deduplication, backups, and migrations contain business invariants that must not be guessed.

## Responsibility map

### `src/include/transport`

Own WebSocket connections, multiplexed streams, request envelopes, routing, handler dispatch, protocol errors, and top-level failure reporting. Keep domain rules out unless they are truly transport-wide gates such as authentication, lockdown, replay protection, or connection admission.

`RequestHandler` and `Result` are established request/audit contracts. Reuse them; do not add another generic response or handler interface.

### `src/include/domains/<domain>/handlers`

Adapt validated requests to domain behavior: authorize, open the appropriate session/transaction, call domain operations, emit protocol responses, and return audit information. A handler may contain one-use orchestration. It does not need a command function merely to make it mockable.

### `commands`, `queries`, validators, guards

Use `commands` for named reusable mutations, state transitions, and domain invariants. Use `queries` for substantial reusable reads and composable SQL. Use validators for boundary/domain validation and guards for reusable access/security decisions.

Do not mechanically move every SQL statement out of handlers. Extract when the operation is reused, has an independent invariant or transaction contract, or is complex enough to have a stable domain name.

### `src/include/database/models`

Own mappings, relationships, database constraints, and entity-local behavior. Do not turn models into transport objects. Prefer database constraints plus `IntegrityError` translation for race-safe uniqueness rather than preflight-only checks.

The global `Session` event filters soft-deleted folders/documents unless `include_deleted` is set. Account for that when diagnosing “missing” rows; do not add duplicate status filters blindly.

### `src/include/providers`

Reuse `Provider`, `StorageProvider`, `CacheProvider`, `EventProvider`, their concrete implementations, and the provider manager. Add a provider abstraction only for a genuine interchangeable backend—not to wrap one call or simplify a test patch.

### `src/include/extensions`

Reuse `ServerHookSpecs`, existing hook timing, and manifest discovery. Extensions are selected by manifest identifier and may own background lifecycle. Do not import optional extension dependencies into core startup paths.

Hook timing is a contract:

- `ext_before_file_upload_finalize` runs inside the caller-owned upload transaction; implementations may write through the supplied session but must not commit or close it.
- `ext_on_file_uploaded` runs after commit and before the success response.
- `ext_on_file_upload_completed` runs after acknowledgement and cannot change the client result.
- startup/shutdown hooks must preserve the documented ordering; shutdown implementations are idempotent.

### `src/maintenance`

Own Typer CLI workflows, backup/export/import, runtime loading, and operator-facing errors. Keep optional provider imports lazy where the current architecture avoids loading unused backends.

### `src/include/config`

Own settings loading, defaults, typed policy objects, and validation. Configuration is untrusted input. Reject unknown/invalid shapes deliberately, but do not duplicate validation throughout domain code after construction of a validated policy object.

## Transaction and concurrency rules

- Make one layer clearly own each transaction. A reusable command/query receiving a `Session` normally participates in the caller's transaction and does not call `commit()`, `rollback()`, or `close()`.
- Keep filesystem/provider side effects ordered with database commits according to the documented lifecycle. Do not claim atomicity across systems that do not share a transaction.
- Use conditional `UPDATE` plus `rowcount`, unique constraints, or locks for competing state transitions. A prior `SELECT` is not a lock unless the database and query explicitly make it one.
- Never pass one SQLAlchemy session between threads. Do not assume the GIL makes compound state changes safe.
- Preserve explicit locks around shared in-process collections and state managers.
- Treat cleanup after acknowledgement as best effort with logging/retry; do not retroactively report client failure after a committed/acknowledged operation.
- Do not leak live ORM objects beyond a session lifetime. The recent `ClaimedFileTask` immutable snapshot is the established pattern when transfer code needs selected data after expiring the ORM instance; it also hides the encryption key from `repr`.

## Abstraction decisions

Use this test before adding a symbol:

1. Can an existing project type/function express the semantics directly?
2. Does the proposed abstraction name a stable domain concept rather than an implementation step?
3. Does it centralize an invariant, composition, lifecycle, transaction, or multiple production uses?
4. Would it still be valuable if tests could not patch or call it?
5. Does it reduce dependency knowledge rather than add another hop?

If answers 2–4 are no, keep the operation at its call site. Line count alone is not evidence for extraction. Conversely, do not keep unrelated state machines, query construction, storage lifecycle, and response formatting fused merely to avoid functions; split along ownership boundaries, not arbitrary size targets.

Avoid these shapes without concrete evidence:

- `FooService` forwarding to a command/model/provider;
- repository classes wrapping `Session.get`, `Session.scalars`, or one `select`;
- a protocol with one implementation and no credible backend seam;
- `safe_*`, `try_*`, and `maybe_*` variants that silently discard errors;
- generic `Result`, `Response`, or `Manager` types duplicating established contracts;
- helpers whose only production body is `return dependency.operation(...)`.

## Change-specific checks

### Handlers and protocol

Trace request schema → authentication/authorization → transaction → response → audit → extension hooks. Verify status code, response data, message sensitivity, and partial-success behavior. Do not expose internal risk reasons, secrets, paths, exception text, or identifiers beyond the documented contract.

### Database and migrations

Inspect all supported dialect branches, naming conventions, soft-deletion criteria, existing indexes/constraints, upgrade data shape, and downgrade limits. Generate revisions through Alembic autogenerate before editing. Use disposable databases for migration tests and preserve the real `src/app.db`.

### Uploads and storage

Read `docs/DOCUMENT_UPLOAD_LIFECYCLE.md`. Preserve the state machine, reachability semantics, resumability, deadlines, commit/response hook ordering, and deferred cleanup. Do not infer file ownership from a transfer task.

### Extensions

Read `docs/EXTENSIONS.md`, both the hook spec and all implementations. Keep annotations as explicit strings when a hook type is imported only under `TYPE_CHECKING`.

### Backups

Treat archive paths, manifests, digests, encryption, extraction roots, schema versions, and restore ordering as hostile-input boundaries. Preserve path traversal defenses and fail closed on integrity errors. Do not change compression or archive format without an explicit compatibility/migration decision.
