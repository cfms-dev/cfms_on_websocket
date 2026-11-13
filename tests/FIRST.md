# FIRST checks

FIRST means Fast, Independent (or Isolated), Repeatable, Self-validating and
Timely. We enforce the first four through test design and repeatable checks.
Timely remains a development practice, without a CI timing-of-authorship rule.
The original [FIRST card](https://media.pragprog.com/titles/olag/properties.pdf),
[pytest fixture guidance](https://docs.pytest.org/en/stable/how-to/fixtures.html#safe-fixture-structure),
[flaky-test guidance](https://docs.pytest.org/en/stable/explanation/flaky.html), and
[Google's behavior-focused testing guidance](https://abseil.io/resources/swe-book/html/ch12.html)
inform these checks. Test layers have different costs; no fixed pyramid ratio,
mock quota, or assertion count replaces a behavior review.

## Fast feedback

`tools/check_test_health.py` starts a fresh pytest process, times startup through
exit, and saves JUnit XML plus a JSON timing/result report. Pytest retains its
normal failure status; failed runs are never automatically retried. Each run
reports the 25 slowest setup/call/teardown phases. The 120-second per-case watchdog
is a final safeguard, not a performance budget or a substitute for cleanup.

```powershell
uv run --locked python tools/check_test_health.py run --profile unit --report test-results/unit.xml
uv run --locked python tools/check_test_health.py run --profile component --report test-results/component.xml
uv run --locked python tools/check_test_health.py run --profile integration --report test-results/integration.xml
```

Follow the database snapshot instructions in [the test guide](README.md) before
all pytest runs, including invocations through this tool.

Each profile has an explicit whole-process feedback limit in
`tools/check_test_health.py`:

| Profile | Time limit |
| --- | --- |
| unit | 30 seconds |
| component, integration | 420 seconds each |
| all non-stress tests | 900 seconds |
| Redis, S3 | 60 seconds each |
| MySQL 8.4, MySQL 9.7 | 300 seconds each |
| PostgreSQL | 120 seconds |
| Each independent protocol node | 60 seconds |

A limit breach fails the command even if pytest passed. JSON reports preserve
both the pytest exit status and the overall check status, elapsed time and limit,
Python version and platform. Every run checks the current source once; the tool
needs no Git history, calibration files, cached measurements or lockfile reader.

The initial layer limits leave headroom above observed Windows runs (roughly
10 seconds for unit and 250–270 seconds for each larger layer). Backend limits
are feedback constraints to verify in the dedicated service jobs. Adjusting a
limit requires a reviewed change justified by the affected test cost. These
limits constrain total feedback time; slowdowns below a limit remain visible in
timing reports and require review rather than an automatic relative comparison.

## Independence and repeatability

Prefer the existing entity factories. Direct protocol creation tests register
identifiers in `owned_entities` as soon as success is established. Cleanup runs
after body failures, attempts every owned entity, and reports failures. It never
clears all server state: audit history and unrelated resources may coexist.
Components own disposable engines/sessions; real concurrency keeps separate
sessions and real commits. Mutated global settings must be restored.

Authentication fixtures reuse immutable password hashes, TOTP secrets and backup
code material within one pytest process, keyed by password and pepper. They use
the normal Argon2 parameters and ten backup codes. Every case still creates its
own accounts, credentials, database, policies, tokens and caches. Tests of password
changes, TOTP setup, rehashing, backup-code consumption and concurrency retain
the real operations; only preparation of already-existing credentials is shared.

CLI fixtures build module-local temporary database templates with the existing
schema and seed logic. Each case uses SQLite backup to create its own database,
configuration and filesystem tree; no live engine or connection is shared.
Permission/audit readback uses fresh SQLite connections, while password checks
and the CLI commands remain real subprocesses. Auxiliary `uv run --no-sync`
calls reuse the locked environment already prepared by the outer test command.
Migration upgrade/downgrade chains and their data/constraint assertions remain
unchanged. Template and authentication-material isolation have behavioral tests.

The `totp_time` fixture fixes PyOTP's default generation and verification time
while retaining its real algorithms and explicit `for_time` arguments. Use it
for in-process TOTP behavior; real server protocol tests retain real clocks and
the production validity window. Prefer established `now=` arguments elsewhere.
Keep ordinary timestamps when their actual value cannot affect the result.
Use events, barriers and bounded joins to coordinate workers, and assert their
effects. Unhandled thread exceptions and unraisable finalizer exceptions fail
pytest instead of appearing only as warnings.

```powershell
uv run --locked python tools/check_test_health.py run --profile all --seed 17 --report test-results/shuffled.xml
uv run --locked python tools/check_test_health.py isolate --report test-results/isolated.xml
```

The seed sets both Python hash randomization and pytest-randomly ordering before
test collection. Security nonces and resource names keep cryptographic entropy;
assertions must not rely on their bytes. Independent-node checks start a fresh
pytest/server session for each of eight access, search and TOTP scenarios.

PR, push and release-call CI run unit, component and integration in independent
jobs, each once in shuffled order seeded from the first eight hexadecimal digits
of the tested commit. The unit job provides its own fast result; the existing
`test (3.15)` check succeeds only when every layer succeeds. There is no additional
whole-suite PR run. Each layer uploads separate timing, JUnit and log artifacts.
pytest-randomly shuffles modules, classes and functions within those groups; this
is not an arbitrary permutation of all individual nodes.
Daily at 19:00 UTC (03:00 Asia/Shanghai the following day), and on manual workflow
dispatch, seeds 1, 17 and 101 run with disposable Redis, MySQL 8.4, PostgreSQL and
S3 services instead of the ordinary layer jobs. A separate job checks the eight
independent nodes once, without repeating them for each seed. Scheduled workflows
run on the default branch; use manual dispatch to validate the daily path before
merging. Ordinary backend jobs retain
both MySQL 8.4 and 9.7. Each dedicated backend profile requires connection
configuration, at least one executed case, and zero skips. Optional unconfigured
backends may still skip during an ordinary local whole-suite run.

## Self-validating results

Assert exact status codes, structured fields, durable state, rollback and absent
forbidden effects. Response messages, Pydantic `msg` text and authentication
messages are diagnostics only. Expected values must be independent of the
implementation. Several assertions may describe one coherent behavior; a
helper assertion, `pytest.raises`, or a deliberate no-exception contract is
valid without a literal `assert` in the body.

S3 CI uses the official [SeaweedFS mini setup](https://github.com/seaweedfs/seaweedfs/wiki/Quick-Start-with-weed-mini).
Readiness checks the dedicated bucket with bounded I/O. Tests register object
cleanup before writes, register multipart aborts immediately after acquisition,
exercise an actual resumed upload, and close clients even after failures.

## Contract preservation

| Changed area | Preserved behavior and added evidence |
| --- | --- |
| Test layers | Existing Pyright, configuration-import, extension-import and Alembic subprocess assertions remain; their layer becomes integration. |
| Entity ownership | Existing access/search/recycle-bin/document/directory assertions remain; identifiers now survive body failure for cleanup. Unit probes cover failed upload, body failure, dependency order and partial cleanup failure. |
| Extra client connections | Document permissions, diagnostics lockdown and broadcast-event assertions remain; `client_factory` registers disconnect before connection/authentication can fail. |
| Security and authorization time | Existing authentication, TOTP and access assertions remain; fixed component clocks and adjacent-window cases replace timing luck. |
| Database namespace | Same-name creation still commits; a new session verifies both persisted documents and their parents. |
| Real S3 | Read/write/abort assertions remain; actual resume, complete content, multipart absence and object cleanup are added. |
| Feedback controls | Synthetic JUnit, failed subprocesses, exceeded time limits and background errors verify that checks reject false green results. |

No production protocol, transaction, password strength or authorization policy
changes are required. Reordering and repeated passing runs supply evidence;
they do not prove that a suite can never be flaky.
