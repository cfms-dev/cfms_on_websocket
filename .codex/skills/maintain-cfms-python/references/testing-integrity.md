# Testing integrity

## Contents

- Authority and failure triage
- Test design rules
- Mocking and testability
- CFMS test tiers and hazards
- Safe execution
- Review checklist

## Authority and failure triage

A test is an executable claim, not automatically the correct specification. Establish authority in this order:

1. explicit current user/product requirement;
2. protocol and security contract;
3. current project documentation and configuration schema;
4. database constraints, migrations, and documented state machines;
5. production behavior that is intentional and corroborated by call sites/history;
6. test expectation.

When sources conflict, do not guess. Present the conflict and evidence or obtain human confirmation if it materially changes business behavior.

For a failure:

1. Run the narrowest node and capture the complete assertion, traceback, logs, and warnings.
2. Determine whether failure occurs in arrange, act, assert, or teardown. A fixture error is not evidence that the business behavior failed.
3. Reproduce without unrelated fixtures/mocks where possible.
4. Trace the actual contract through schema → handler → command/query/model → persistence/effect → response.
5. Check patch namespace, leaked global state, clock/randomness, thread completion, database filters, transaction boundaries, and test order.
6. Classify the defect as production, test, environment, or unresolved contract.
7. Change the owning side only. Never weaken a business invariant to satisfy a stale or incorrect assertion.

For a regression fix, make the test fail on the old code for the intended reason before relying on it. If a test already passed before the change, explain what new risk it covers; otherwise it may be a placebo.

## Test design rules

Assert observable behavior at the lowest useful layer:

- pure domain functions: decisions and edge cases;
- commands/state machines: returned domain result plus persisted transition;
- queries: result contents, ordering, filtering, and dialect-relevant semantics;
- handlers: response code/data, authorization, audit target, and committed effects;
- integration client: public protocol behavior across the WebSocket boundary;
- migrations: pre-upgrade data → upgrade → constraints/data → downgrade limitations.

Prefer one meaningful act per test. Parameterize genuine input/output partitions, not arbitrary line reduction. Keep expected values independent from the implementation algorithm.

Reject or rewrite tests with any of these defects:

- no assertion or an assertion that is always true;
- expected values produced by the same code/algorithm being tested;
- only checking that a newly extracted wrapper forwards to its mocked dependency;
- asserting private call order when the public outcome is the contract;
- catching all exceptions and passing, returning early, or silently skipping the assertion;
- mocking every collaborator until no production behavior runs;
- asserting the mock configuration rather than the system response/state;
- changing production behavior solely to expose a patch point;
- fixed `sleep()` used as proof that concurrent work finished;
- broad assertions such as “code is not 500” when an exact outcome is specified;
- snapshotting unstable fields wholesale when only a few contract fields matter.

Use `pytest.raises(..., match=...)` for an expected exception and assert relevant postconditions. For partial success, assert both successful and failed members plus durable side effects. For security behavior, assert that sensitive detail is absent as well as the correct rejection.

## Mocking and testability

Prefer real pure-domain code, temporary files, disposable SQLite databases, existing fakes, and established provider seams. Mock only a boundary whose real behavior is slow, nondeterministic, destructive, external, or separately covered.

Patch the name where the system under test looks it up, not necessarily where it was defined. Keep `raising=True` unless absence is the scenario under test. When using `unittest.mock`, prefer `autospec=True` / `spec_set` when safe so nonexistent APIs and wrong signatures fail; never use `create=True` merely to make a missing production API appear valid.

Do not introduce dependency injection, a protocol, wrapper, clock class, repository, or helper solely because a test wants to patch one expression. First use an existing boundary, pass an already meaningful value (for example the established `now=` keyword on state transitions), or assert the observable result. Add an injectable dependency only when production also benefits from an explicit interchangeable dependency or deterministic domain input.

Avoid patching SQLAlchemy query-chain internals. Prefer seeding rows and observing results. Patch a documented project boundary only when the test specifically verifies race/error translation that cannot be produced portably; keep that test alongside a behavioral database test.

## CFMS test tiers and hazards

The root `tests/conftest.py` has session-scoped fixtures that:

- write a test `src/config.toml` and later restore the original;
- delete `src/init`, `src/app.db`, and `src/admin_password.txt` before server startup;
- start a real server subprocess;
- recreate runtime directories and state.

Therefore any pytest invocation can collect/use fixtures that destroy the existing SQLite runtime database. Do not assume a single test file is harmless without reading its fixtures and imports.

Distinguish common tiers:

- pure/unit tests: no global config/database/server import side effects;
- disposable database tests: construct an engine/session against `tmp_path` or in-memory SQLite;
- handler tests: patch a narrow transport boundary and use disposable persistence;
- integration tests: use `client`, `authenticated_client`, factories, or `server_process` and start the real server;
- migration tests: run Alembic/subprocesses against copied or temporary databases;
- stress tests: explicit `tests/stress` commands, never part of routine validation.

Do not use marker names as proof of tier; the declared `unit`, `integration`, `slow`, and `stress` markers are not consistently applied across the existing suite. Inspect fixtures directly.

The suite and production code use threads. Join spawned threads or wait on an explicit event/state with a bounded timeout. Pytest helpers are not thread-safe when invoked concurrently. Tests that mutate globals cannot safely run in parallel without isolation.

## Safe execution

Before any pytest command:

1. Stop or account for a running CFMS server. A concurrent writer can make both tests and restoration unsafe.
2. If `src/app.db` exists, run:

   ```powershell
   uv run --locked python .codex/skills/maintain-cfms-python/scripts/snapshot_test_state.py
   ```

3. Record and protect the printed directory; it may contain the database, configuration, and admin credential material.
4. Run the narrowest node: `uv run --locked pytest tests/test_file.py::test_name`.
5. Expand to the related file/domain only after the narrow result is understood.
6. Run the full suite only when necessary because it is slower and broadens destructive state changes.

The snapshot script uses SQLite's online backup API so committed WAL content is included; it does not copy `-wal`/`-shm`, restore files, or overwrite the project. Restoration is a separate deliberate action and must not occur while a service is using the database.

Do not run Ruff directly. If formatting/lint validation is warranted, run the repository pre-commit hooks and inspect their edits. Do not conceal dependency warnings with the repository's existing `--disable-warnings` pytest output setting; run a focused warning check when deprecation work is in scope and attribute each warning to project or dependency code.

## Review checklist

- Does each new test fail against the defect/old behavior for the intended reason?
- Does it assert a documented observable contract and durable postconditions?
- Is the expected value independent from the implementation?
- Are fixtures minimal, explicit, and cleaned up even on failure?
- Is each patch applied where the name is looked up and limited in scope?
- Would the test still be valuable after a private refactor?
- Did any production-only abstraction appear solely to satisfy this test?
- Does a failing existing test conflict with higher-authority business evidence?
- Are race tests synchronized by state/events rather than timing luck?
- Was the runtime database snapshotted before pytest and the location reported?

## Primary sources

- [pytest fixture design](https://docs.pytest.org/en/stable/explanation/fixtures.html)
- [pytest monkeypatch guidance](https://docs.pytest.org/en/stable/how-to/monkeypatch.html)
- [pytest flaky-test causes](https://docs.pytest.org/en/stable/explanation/flaky.html)
- [`unittest.mock`: where to patch and autospec](https://docs.python.org/3.14/library/unittest.mock.html#where-to-patch)

Pytest documents fixtures as explicit, modular contexts and warns that unrelated fixture dependencies obscure failures. Its flaky-test guide identifies uncontrolled system state, test-order dependence, global mutation, thread lifetime, and overly strict timing assertions as common causes. Python's mock docs warn that `create=True` can make tests pass against APIs that do not exist.
