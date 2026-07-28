---
name: maintain-cfms-python
description: Maintain, implement, refactor, review, debug, or test Python code in the CFMS on WebSocket repository while preserving its architecture, business contracts, transaction boundaries, and test integrity. Use for changes to src/, tests/, tools/, Python dependencies, Alembic migrations, WebSocket handlers, SQLAlchemy queries/models, Pluggy extensions, providers, maintenance commands, or Python-version policy; especially when a failing test, proposed abstraction, deprecation, Python 3.14+ feature, compatibility concern, or defensive check could tempt an agent to distort correct behavior or add unnecessary wrappers.
---

# Maintain CFMS Python

## Work from evidence

Preserve the simplest design that expresses the verified business contract. Treat tests as evidence, not as the source of truth. Reuse the repository's existing boundaries before introducing a new layer, interface, helper, result type, or compatibility path.

Before changing code:

1. Confirm the host OS and obey the nearest `AGENTS.md`.
2. Inspect `git status` and preserve unrelated user changes.
3. Read `pyproject.toml`, `.python-version`, `uv.lock`, relevant docs, the complete call path, nearby tests, and recent history when intent is unclear.
4. Query exact installed versions with `importlib.metadata.version()` or the package's documented API. Do not infer behavior from a minimum dependency constraint.
5. Use `rg` / `rg --files` to locate existing implementations, schemas, hooks, provider contracts, query helpers, and test fixtures.
6. State the contract being preserved or changed before choosing an implementation.

Always read [project-architecture.md](references/project-architecture.md). Read [python-314-and-later.md](references/python-314-and-later.md) for syntax, typing, standard-library, deprecation, or compatibility work. Read [testing-integrity.md](references/testing-integrity.md) before adding, changing, running, or interpreting tests. Read [versioned-apis.md](references/versioned-apis.md) when touching dependencies or framework APIs.

## Choose the smallest coherent change

Keep behavior near the responsibility that owns it:

- Keep protocol parsing, authentication gates, response emission, and audit orchestration in transport/handlers.
- Keep reusable domain mutations and invariants in `domains/*/commands` when they have domain meaning beyond one call expression.
- Keep reusable database reads and composable SQL in `domains/*/queries`.
- Keep persistence shape and true entity-local invariants in database models.
- Keep backend variation behind the existing provider contracts.
- Keep optional lifecycle behavior behind existing Pluggy hooks and extensions.

Do not force every handler into command/query helpers. Extract code only when the extracted unit owns at least one of:

- a reusable domain operation or invariant;
- a transaction, resource, retry, or state-machine boundary;
- meaningful composition of several operations;
- a complex query with a stable domain name;
- behavior used by multiple production call sites.

Do not extract a function merely to patch it, assert that it was called, shorten a test, wrap one library call, or make a long function look numerically smaller. Do not introduce a service, repository, manager, factory, adapter, protocol, DTO, or result wrapper when `Session`, `RequestHandler`, `Result`, provider bases, hook specs, dataclasses, or direct standard-library facilities already provide the required semantics.

## Keep coupling intentional

Prefer explicit inputs and return values at existing boundaries. Pass a caller-owned SQLAlchemy `Session` into reusable commands/queries; do not commit, close, or replace it unless the function explicitly owns the transaction. Keep ORM objects inside a valid session lifetime, or return an intentional immutable snapshot when data must outlive it.

Use dataclasses or enums only when they name a real state, decision, or immutable cross-boundary value. Keep secrets out of representations with `field(repr=False)`. Avoid generic containers or `Any` when a stable domain shape exists, but do not create a type solely to rename a one-use dictionary.

Prefer direct imports and existing project facilities. Place imports at the top except for a documented lazy-loading or circular-import boundary already used by the project. Combine context managers with the same lifetime into one `with` statement.

## Validate at trust boundaries

Validate untrusted WebSocket payloads, configuration, extension manifests, file/archive contents, network input, credentials, and migration preconditions. Enforce concurrency invariants with database constraints, conditional updates, transactions, or the existing locks—not with check-then-act Python branches.

Inside a trusted call path, rely on established types and preconditions. Do not add redundant `isinstance`, `getattr`, `hasattr`, `None`, range, or catch-all checks “just in case.” Add a guard only when it prevents a plausible state from crossing a named boundary and define the resulting behavior.

Catch exceptions only where code can recover, roll back, clean up, translate into the protocol/domain vocabulary, isolate an extension, or add actionable context. Preserve causes with `raise ... from exc`. Allow unexpected failures to reach the existing top-level reporting boundary instead of converting them into empty results, false success, or silent fallbacks.

## Apply Python 3.14 deliberately

Target the declared floor (`>=3.14`), not the newest interpreter installed elsewhere. Follow these defaults:

- Do not add `from __future__ import annotations`; the repository tests prohibit it and Python 3.14 evaluates annotations lazily.
- Leave ordinary forward references unquoted. Keep explicit string annotations for Pluggy hook specs/implementations when their types exist only under `TYPE_CHECKING`; Pluggy registration calls `inspect.signature()` and can trigger evaluation on Python 3.14.
- Use `annotationlib.get_annotations()` for runtime annotation inspection rather than reading or mutating `__annotations__`.
- Prefer built-in generics, `X | None`, modern type-parameter syntax, `Self`, `StrEnum`, and focused dataclasses when they clarify an existing contract.
- Use `datetime.datetime.now(datetime.UTC).date()` for the current date and the `datetime.UTC` alias for UTC.
- Do not adopt a new language or standard-library feature merely because it exists. Require a concrete readability, correctness, security, dependency, or performance benefit.
- Do not use Python 3.15-only syntax or APIs while 3.15 is a prerelease and the project floor remains 3.14.

Check the live Python deprecation index and the exact dependency version's official docs before calling an API deprecated. Do not churn code whose API is merely older-looking but still supported. Never depend on private implementation names when a public introspection API exists.

## Protect test truth

For every behavior change, write the intended observable contract in plain language first. Add or update tests that would fail on the pre-change behavior for the intended reason. Prefer assertions on protocol results, persisted state, state transitions, emitted effects, and security invariants over assertions about private helper calls or SQL construction details.

When a test fails, do not immediately edit production code. Reproduce the smallest case, identify the authoritative contract, inspect setup/teardown and patch targets, and decide whether the defect is in production, the test, or the environment. If a test contradicts a verified business rule, correct the test and document the evidence; never make correct business code wrong to satisfy it.

Reject tests that are tautological, assert only their own mocks, swallow the exception under test, duplicate the implementation to compute the expected value, always pass, or exist only to exercise a test-induced wrapper. Avoid sleeps as synchronization when an event, join, state transition, or bounded poll expresses the real condition.

## Validate safely and proportionally

Do not run pytest before reading [testing-integrity.md](references/testing-integrity.md). The session fixture deletes and recreates runtime data. If `src/app.db` exists, create a consistent snapshot first:

```powershell
uv run --locked python .codex/skills/maintain-cfms-python/scripts/snapshot_test_state.py
```

Record the printed snapshot path. Run the narrowest relevant tests first with `uv run --locked pytest <path-or-node-id>`. Expand only when the change's dependency surface warrants it. Do not hide or globally suppress deprecation warnings; determine whether the project or a dependency owns each warning.

Do not run Ruff directly. Run the repository's pre-commit hooks only when appropriate, then inspect every automatic edit. For Alembic changes, first run `uv run alembic revision --autogenerate`, then edit the generated revision and test both upgrade and downgrade against disposable data.

Before handing off:

1. Review the diff for unrelated churn, redundant comments, speculative compatibility, wrapper-only functions, widened exception handling, and accidental contract changes.
2. Confirm tests assert behavior rather than the implementation shape introduced by the patch.
3. Report commands run, results, warnings, skipped validation, and the runtime snapshot path.
4. Distinguish verified facts from remaining assumptions.

## Resolve common conflicts

- If a test expects behavior that contradicts protocol docs, migrations, security invariants, or an explicit requirement, stop and reconcile the contract; do not “split the difference.”
- If modern syntax breaks runtime introspection, retain the minimal documented exception at that framework boundary.
- If removing a defensive branch exposes an impossible state, prefer a clear invariant failure over a silent fallback.
- If an abstraction has only a test caller and one production forwarding call, inline it unless it owns meaningful domain semantics or lifecycle.
- If a dependency upgrade suggests a rewrite, verify the locked version, migration guide, warnings, and behavior before changing imports or architecture.
