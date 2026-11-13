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

CI uses a pinned reference commit from `first-baseline-ref.txt`. On a cache miss,
the composite action checks out that commit into `.first-baseline`, executes
three clean sessions using the candidate's locked environment, and caches those
reference measurements. Imports and subprocesses use the reference checkout's
source paths, rather than the candidate's editable installation. The environment
fingerprint includes the exact Python version, platform/architecture, runner
image version and lockfile hash; the cache also includes the checker hash,
profile and reference commit. A mismatch fails validation.

For median reference time `B`, the budget is `max(1.5 * B, B + allowance)`:

| Profile | Allowance |
| --- | --- |
| unit | 5 seconds |
| component | 15 seconds |
| integration, Redis, each MySQL version, PostgreSQL, S3 | 30 seconds |

Candidate execution cannot update a baseline. Changing the pinned reference
requires a reviewed commit explaining legitimate coverage or cost changes.
Cache misses, including runner-image updates, cost three additional reference
runs; warm runs execute only the candidate. This is a coarse feedback regression
check, not an application benchmark.

For local calibration, make a disposable checkout of the pinned reference and
pass its path to `--root`; the tool verifies its Git HEAD before measuring:

```powershell
uv run --locked python tools/check_test_health.py calibrate --profile unit --root .first-baseline --baseline test-results/unit-baseline.json --report test-results/reference-unit.xml
uv run --locked python tools/check_test_health.py run --profile unit --baseline test-results/unit-baseline.json --report test-results/unit.xml
```

## Independence and repeatability

Prefer the existing entity factories. Direct protocol creation tests register
identifiers in `owned_entities` as soon as success is established. Cleanup runs
after body failures, attempts every owned entity, and reports failures. It never
clears all server state: audit history and unrelated resources may coexist.
Components own disposable engines/sessions; real concurrency keeps separate
sessions and real commits. Mutated global settings must be restored.

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

PR CI runs ordinary layers and one shuffled suite seeded from the tested commit.
Daily at 19:00 UTC (03:00 Asia/Shanghai the following day), and on manual workflow
dispatch, seeds 1, 17 and 101 run with disposable Redis, MySQL 8.4, PostgreSQL and
S3 services, followed by independent-node checks. Ordinary backend jobs retain
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
| Security and authorization time | Existing authentication, TOTP and access assertions remain; fixed component clocks and adjacent-window cases replace timing luck. |
| Database namespace | Same-name creation still commits; a new session verifies both persisted documents and their parents. |
| Real S3 | Read/write/abort assertions remain; actual resume, complete content, multipart absence and object cleanup are added. |
| Feedback controls | Synthetic JUnit, failed subprocesses, invalid baselines, exceeded budgets and background errors verify that checks reject false green results. |

No production protocol, transaction, password strength or authorization policy
changes are required. Reordering and repeated passing runs supply evidence;
they do not prove that a suite can never be flaky.
