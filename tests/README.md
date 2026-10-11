# CFMS test suite

The suite checks the public WebSocket protocol, domain behavior, persistence,
providers, maintenance commands, deployment artifacts, and the test tools.
Python 3.15 and the locked development dependencies are required:

```powershell
uv sync --locked --dev --all-extras
```

## Layers and selection

Every test has exactly one layer marker. A module can use `pytestmark` when all
its cases have the same layer; mixed modules mark individual cases. Collection
rejects missing or conflicting layer markers and rejects `unit` or `component`
cases that depend on the integration server through their fixture dependencies.

| Marker | Behavior under test | Examples |
| --- | --- | --- |
| `unit` | Pure decisions, serialization, and collaborators replaced at existing boundaries | Trigger calculations, in-memory rate limits, fake Redis/S3 behavior |
| `component` | Real in-process SQLite, filesystem, archives, or handlers with disposable resources | Visibility queries, persisted state transitions, backup restoration, local storage |
| `integration` | Real subprocesses, WebSocket/HTTP connections, or external backends | Protocol authentication, maintenance CLI, server lifecycle, Redis Lua, MySQL/PostgreSQL concurrency |

`slow` is an additional cost annotation, not a layer. `stress` identifies actual
load execution. The ordinary tests under `tests/stress/` check the load tools;
they belong to `unit` or `component` and do not run load scenarios.

Before invoking pytest, follow `AGENTS.md`: account for any running development
server and snapshot `src/app.db` if it exists:

```powershell
uv run --locked python .codex/skills/maintain-cfms-python/scripts/snapshot_test_state.py
```

Protect the printed snapshot directory; it can contain credentials. Restoration
is a deliberate manual operation and must not run while a service uses the data.

Run the narrowest relevant case first, then the affected layer or domain:

```powershell
uv run --locked pytest tests/providers/test_request_rate_control.py
uv run --locked pytest tests/ -m "unit and not stress"
uv run --locked pytest tests/ -m "component and not stress"
uv run --locked pytest tests/ -m "integration and not stress"
uv run --locked pytest tests/ -m "not stress" --junitxml=test-results/all.xml --durations=25
```

A WebSocket node example is
`tests/integration/test_basic.py::TestAuthentication::test_login_success`.
The suite uses strict pytest configuration and markers. Async tests retain
`@pytest.mark.asyncio`; async fixtures use `pytest_asyncio.fixture` and function
loop scope.

## Runtime and ownership

Before test modules are collected, the session copies server code and required
resources to a temporary `cfms-pytest-*` tree, writes its test configuration, and
patches the application's runtime paths. It excludes development configuration,
databases and WAL files, admin credentials, uploaded content, logs, and server
private keys. Import-time configuration and database initialization therefore
resolve into the disposable tree, including during unit/component collection.
The working checkout's runtime files are not recreated by normal pytest runs.

The real server starts only when requested through `server_process`, normally by
`client_factory` or another WebSocket fixture. It is shared for the session;
client connections and owned users, groups, documents, and directories are
function-scoped. Use `client_factory` for extra connections and the entity
factories for resources that need cleanup. Factories clean their recorded objects
in reverse order and report cleanup failures after attempting every object.

Server readiness requires a successful WebSocket handshake. Teardown stops the
subprocess, closes its pipes/log readers, stops imported configuration observers,
disposes the imported database engine, restores path/environment patches, and
removes the temporary tree. Disposable component databases own their engine and
sessions; no ORM object or worker should outlive that ownership boundary.

`CFMSTestClient` has a keyword-only `response_timeout=10.0`, used for ordinary
requests, raw requests, file protocol frames, and default event waits. An event
can pass `accept_event(..., timeout=...)` when its expected delay is longer.

The global pytest timeout is a 120-second final watchdog covering setup, the test,
and teardown. Server startup has a 20-second deadline; stop waits up to 5 seconds
before killing and another 5 seconds afterward. Client receive deadlines and
bounded events/joins provide the ordinary failure path. Use a justified local
timeout override for an intentionally longer scenario. The timeout plugin chooses
the platform method: Windows may terminate the whole pytest process and skip
teardown, so the watchdog does not replace resource cleanup or bounded I/O.

## Writing and refactoring tests

1. Establish the contract from current requirements, protocol/security documents,
   configuration, database constraints, and verified call paths. A stale assertion
   must not change correct production behavior.
2. Assert one coherent observable outcome at the lowest useful layer: returned
   decisions, exact protocol results, persisted state, events, and durable
   postconditions. Several assertions can describe one behavior.
3. Cover meaningful partitions: success, authorization/validation failures,
   boundaries, partial effects, rollback, and concurrency ownership. Parameterize
   genuine input/output partitions rather than unrelated workflows.
4. Keep expected values independent of the implementation. Avoid broad assertions
   such as “not 500” when the contract specifies a result; do not swallow the
   exception or inspect only the configured mock.
5. Use real pure code and disposable persistence. Mock external or nondeterministic
   boundaries, patch where a name is looked up, and use a spec when appropriate.
   Real dialect, Redis Lua, and storage compatibility behavior needs real backend
   tests as well as local fakes.
6. Register cleanup immediately after acquiring a resource, including setup failure
   paths. Use existing fixtures, context managers, `ExitStack`, and `try/finally`.
   Capture worker exceptions in the test thread and wait on events/barriers or
   state with a deadline; a fixed sleep does not prove completion.
7. Share fixtures within their owning domain and ordinary helpers in support
   modules. Do not import a fixture/helper from a collected `test_*.py` module.
   Extract domain setup or resource management when it is genuinely reused, not
   a wrapper that merely forwards one operation.
8. During refactoring, map every changed assertion to its replacement before
   deleting or merging a case. Keep protocol gates in integration tests and
   complex database combinations in component tests. Preserve different layer
   checks when they protect different risks.
9. A regression test must fail against the defect for the intended reason. Review
   warning output, unjoined workers, missing cleanup, and unexpected skips before
   trusting a green run. Run Ruff only through repository pre-commit hooks.

A valid asynchronous example using the existing client is:

```python
import pytest

from tests.support.assertions import assert_error


@pytest.mark.integration
@pytest.mark.asyncio
async def test_unknown_action_is_rejected(client):
    response = await client.send_request(
        "nonexistent_action_xyz_123", include_auth=False
    )
    assert_error(response, 400)
```

The criteria follow [pytest fixture guidance](https://docs.pytest.org/en/stable/explanation/fixtures.html),
[pytest flaky-test guidance](https://docs.pytest.org/en/stable/explanation/flaky.html),
[Python mock guidance](https://docs.python.org/3.15/library/unittest.mock.html#where-to-patch),
and [Google's behavior-focused testing guidance](https://abseil.io/resources/swe-book/html/ch12.html).
A test-count ratio, mock count, line count, or coverage percentage alone does not
justify rewriting a working test.

## Coverage destinations after reorganization

The reorganization keeps domain folders; markers express execution layers.
Existing behavior tests retain their assertions unless a documented replacement
covers the same contract. This table records where the principal risks remain.
The [node inventory](contract_inventory.csv) records every collected parameter
scenario, its contract label, layer, assertion expressions, and source location.
It is a review snapshot, not a coverage percentage or a second executable oracle;
the referenced test remains authoritative. Update it when changing the suite.

| Behavior or risk | Destination | Layer |
| --- | --- | --- |
| Public protocol, login gates, client session separation | `integration/test_basic.py` and domain protocol tests | integration |
| Isolated configuration/runtime and development-file preservation | `config/test_test_config_lifecycle.py` | component |
| Startup failure, log-thread failure, process/pipe cleanup | `integration/test_server_lifecycle.py` | integration |
| Search visibility/filtering and persisted access rules | `domains/documents/test_search_queries.py`, `domains/access/` | component |
| Upload, deduplication, cleanup, and file-task state transitions | `domains/documents/` | component plus distinct integration gates |
| Scheduler contracts and trigger calculations | `scheduling/test_registry_and_triggers.py` | unit |
| Schedule persistence, leases, deletion and local races | `scheduling/test_commands.py`, `test_models.py`, `test_engine.py`, `test_handlers.py` | component; mixed cases are marked individually |
| Shared-database scheduler ownership and atomic initialization | `scheduling/test_engine_shared_database.py` and the shared-database case in `test_engine.py` | integration |
| Memory rate-limit capacity race and provider lifecycle | `providers/test_request_rate_control.py`, local/fake provider tests | unit |
| Real Redis script atomicity, expiry, time and lease ownership | `providers/test_redis_lua_integration.py` | integration |
| Local storage effects, fake S3 behavior, real S3 compatibility | `providers/test_storage_providers.py`, `test_s3_compatibility_integration.py` | component / unit / integration respectively |
| Backup integrity, round trips and migration contents | `maintenance/backup/`, `maintenance/database/` | component; real MySQL cases are integration |
| Shared migration setup formerly imported from another test | `maintenance/database/support.py`, consumed by migration/MySQL tests | support only; not a collected test module |
| Operator-facing maintenance CLI behavior | `maintenance/cli/` | integration; fake console cases are unit |
| Deployment/extension filesystem safety and recovery | `maintenance/deployment/`, `maintenance/extensions/` | component |
| Release artifacts, source boundaries and CI channel selection | `project/` | component plus control unit cases |
| Query-plan tooling | `tools/test_explain_query_plans.py` | component; index declaration case is unit |
| Load-tool metrics/pacing and profile/account-file parsing | `stress/test_ws_load.py`, `test_performance_orchestration.py` | unit / component; no actual stress run |

## External backends and CI

Routine local runs skip optional backend cases when their opt-in environment is
absent. Configured but unavailable backends fail. These URLs must point to
**dedicated disposable services**: SQL fixtures recreate application tables and
Redis fixtures remove only their unique test namespace.

- `CFMS_TEST_REDIS_URL`: `providers/test_redis_lua_integration.py`.
- `CFMS_TEST_MYSQL_URL`: MySQL migration, upload cleanup, rate limits, and shared
  scheduler cases; select the MySQL parameters with `-k mysql`.
- `CFMS_TEST_POSTGRESQL_URL`: shared scheduler cases; use `-k postgresql`.
- S3 compatibility is separately opt-in with `CFMS_TEST_S3_WRITE=1` and a dedicated
  `CFMS_TEST_S3_BUCKET`; see `providers/test_s3_compatibility_integration.py`.

CI runs unit, component, and integration phases with JUnit XML and slow-test
reports. Dedicated Redis, MySQL 8.4/9.7 and PostgreSQL jobs retain real services,
require nonempty connection configuration, and fail if their JUnit report has no
executed cases or contains skips. Windows writeability and release bundle smoke
checks remain in the platform job. Details are in
[the workflow guide](../.github/workflows/README.md).

Actual load runs are explicit commands, separate from pytest. Follow
[the performance guide](../docs/PERFORMANCE_TESTING.md); managed reset mode may
delete state in its selected disposable server tree. The manual performance
workflow compares baseline/candidate revisions on an owner-supplied fixed runner.

## Diagnosing failures

Use the narrow failing node and its complete traceback, warnings, JUnit report,
and `test_logs/` server output. Identify whether the failure is in setup, behavior,
assertion, or cleanup. Check resource ownership, patch targets, fixture dependency,
thread completion, database dialect/filters, and contract authority. Do not hide
cleanup errors or increase timeouts before establishing why the condition was not
reached. Re-run a changed subset in a fresh session before expanding validation.
