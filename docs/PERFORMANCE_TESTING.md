# Performance testing

The performance harness is a black-box WebSocket client stored with CFMS so its
protocol implementation evolves with the server. Pytest verifies the harness
contracts but does not run sustained load. Real load runs use
`tests.stress.ws_load` explicitly.

## Safety boundaries

Managed mode deletes `src/app.db`, generated credentials, and file storage. It
therefore refuses to run from the primary checkout even when `--managed-reset`
is present. Use a linked disposable worktree, or use the local comparison
orchestrator described below, which creates and removes disposable worktrees.

Remote load must never target production. Every remote run requires a target
configuration identifier, an environment classification, and the server commit
and version:

```powershell
uv run --locked python -m tests.stress.ws_load `
    --host cfms-perf.example.invalid --port 5104 `
    --target-id perf-cluster-a --target-environment performance `
    --server-commit 0123456789abcdef --server-version 0.8.0 `
    --profile smoke --scenario server-info --json
```

The hostname above is intentionally non-routable documentation. Remote
mutating scenarios additionally require `--allow-remote-mutations`, and only
accept `--target-environment performance`. This opt-in is an assertion that the
target contains dedicated disposable performance data; it is not permission to
use production records.

Remote TLS verifies the certificate and hostname by default. `--tls-ca-file`
selects a private CA. `--insecure` is limited to an explicitly disposable
target, and `--no-ssl` should be used only on an isolated trusted network.

## Profiles and overrides

Profiles are defined in `tests/stress/profiles.toml` and strictly parsed with
schema version 1:

| Profile | Purpose | Default load shape |
| --- | --- | --- |
| `smoke` | Short correctness and contract check | 2 users, 5 seconds, closed |
| `peak` | Expected peak workload | fixed arrival rate with mixed CRUD |
| `stress` | Step load until the first saturated stage | increasing arrival rates |
| `spike` | Sudden traffic burst and recovery | baseline, spike, recovery |
| `soak` | Long-running stability and leak check | 8-hour fixed arrival rate |

Use `--profile`; explicit CLI values override profile values. Any inherited
value that becomes contradictory still fails validation, so override both
values when needed:

```powershell
uv run --locked python -m tests.stress.ws_load `
    --profile peak --scenario server-info `
    --duration 20s --ramp-up 2s --rate 50 `
    --host $env:CFMS_PERF_HOST --port 5104 `
    --target-id perf-a --target-environment performance `
    --server-commit $env:CFMS_SERVER_COMMIT `
    --server-version $env:CFMS_SERVER_VERSION `
    --output results/peak.json
```

Durations accept seconds as numbers or `ms`, `s`, `m`, and `h` suffixes.
Unknown root/profile/action fields, non-positive durations, negative rates,
non-increasing stress stages, out-of-range spike windows, and incompatible TLS
options are rejected. `--rate` selects fixed-arrival mode; `--rate 0` selects a
closed model. `--stage-rates 25,50,100` selects a step model.

The mixed CRUD weights are `read`, `create`, `update`, and `delete`. Profile
weights may be selectively overridden:

```powershell
--scenario mixed --action-weight read=55 --action-weight create=20
```

## Scenarios and data lifecycle

| Scenario | Measured behavior | Data preparation and cleanup |
| --- | --- | --- |
| `server-info` | Public request baseline | none |
| `auth-read` | Login plus authenticated directory/user/group reads | dedicated account required |
| `multiplex` | Multiple in-flight streams on each connection | none beyond login |
| `mixed` | Weighted directory CRUD | unique `Perf_*` directories; delete and purge |
| `connection-storm` | Repeated connect/request/disconnect | none |
| `reconnect-storm` | Two connect/disconnect cycles per iteration | none |
| `upload-unique` | Unique payload upload | unique document and bytes; delete and purge |
| `upload-duplicate` | Deduplicable payload upload | unique document, shared bytes; delete and purge |
| `upload-resume` | Interrupted upload followed by non-zero resume | reconnect, complete, delete and purge |
| `download` | Upload preparation then file download | dedicated document; delete and purge |
| `download-resume` | Interrupted download followed by non-zero resume | reconnect, complete, delete and purge |
| `admission-control` | Multiplexed pressure and public 503 contract | none |
| `request-rate-control` | Request quota pressure and public 429 contract | none |

Cleanup is best effort and is reported as explicit cleanup actions. A cleanup
error does not rewrite a completed transfer result; inspect those action errors
and service logs. Test accounts must have only the permissions required by the
selected scenario, including purge permissions when zero residue is required.

For a remote account pool, keep usernames in a local TOML file and passwords in
separate environment variables:

```toml
schema_version = 1

[[accounts]]
username = "perf-user-01"
password_env = "CFMS_PERF_PASSWORD_01"

[[accounts]]
username = "perf-user-02"
password_env = "CFMS_PERF_PASSWORD_02"
```

Pass the file with `--accounts-file`. Workers use accounts round-robin. The
result records only pool size, never usernames, environment-variable names,
passwords, tokens, task credentials, private keys, hostnames, or the account
file path. A single account may instead use `--username` or
`CFMS_LOAD_USERNAME`; its password is read from `CFMS_LOAD_PASSWORD` or the
environment variable named by `--password-env`.

## Load models and saturation

Closed mode starts the next iteration after the previous one finishes. Fixed
arrival mode schedules starts at a global rate and spreads slots across users.
If a busy worker misses slots, they are counted as `dropped_iterations`; they
are not silently converted into a lower arrival rate.

Stress profiles divide their duration across increasing rate stages and stop at
the first stage with dropped iterations or less than 99% valid outcomes. Spike
profiles report baseline, spike, and recovery phases separately. The configured
random seed makes mixed action selection reproducible.

Admission and quota scenarios separate valid, expected rejections from actual
errors. Request 429/503 responses are accepted only when they contain the
documented `scope` and positive `retry_after_seconds`; 429 also requires a
positive `limit`. Connection attempt 429 validates the HTTP `Retry-After`
header, while accepted connections rejected for capacity validate close code
1013. Invalid or unexpected responses remain errors.

## Result contract

Result schema version 2 includes:

- the profile name and complete normalized, secret-free parameters;
- UTC start/finish times, measured duration, target configuration identifier,
  and random seed;
- harness commit, generator Python/component versions, server commit/version,
  protocol version, and available server component versions;
- connection attempts, success rate, handshake p50/p95/p99/max, and current and
  peak connection counts;
- independent login latency in `actions.login`;
- per-scenario and per-action request count, success/valid-outcome rate,
  throughput, p50/p95/p99/max, detailed errors, and error categories;
- expected rejection counts separate from errors and dropped iterations;
- transfer bytes, bytes per second, payload size, and file-size group;
- bounded generator event-loop-lag statistics, CPU, RSS, and a generator
  saturation assessment;
- per-phase results and the detected stress saturation phase.

Latency and event-loop-lag storage keeps exact small runs, then switches to a
fixed-size logarithmic histogram. Soak memory use does not grow with request
count. Generator CPU/RSS samples are also bounded.

The result schema deliberately excludes credentials and full target
configuration. Store raw JSON beside separately protected infrastructure
metadata when the target identity requires more detail.

## Comparing repeated runs

`tools/compare_upload_benchmarks.py` retains its existing path but now compares
all scenarios. Baseline and candidate sets must contain the same scenarios,
run counts, normalized parameters, random-seed sets, and one identical harness
commit. Medians are used for throughput, p95, p99, success rate, dropped
iterations, and file throughput.

```powershell
uv run --locked python tools/compare_upload_benchmarks.py `
    results/baseline results/candidate `
    --max-throughput-regression 0.10 `
    --max-latency-regression 0.10 `
    --minimum-success-rate 0.999 `
    --max-dropped-increase 0 `
    --maximum-p95-ms 100 `
    --maximum-p99-ms 250 `
    --minimum-file-bytes-per-second 1048576 `
    --output results/comparison.json
```

`--max-regression` remains a compatibility alias that sets both relative
throughput and latency limits. `--minimum-throughput-rps`, `--maximum-p95-ms`,
`--maximum-p99-ms`, and `--minimum-file-bytes-per-second` are absolute SLOs.
Exit code 0 passes, 1 means a measured threshold failed, and 2 means results
could not be compared. Output is always machine-readable JSON for a valid CLI
invocation.

Older upload result metrics remain readable. Results predating
`harness.commit` cannot prove harness equivalence and receive an explicit
migration error; rerun them or annotate them only when the exact historical
harness commit has been independently verified. Older uploads without file
throughput can still be compared to one another, but cannot satisfy an absolute
file-throughput SLO.

## Local baseline/candidate orchestration

The reusable orchestrator resolves refs, creates two temporary linked
worktrees, materializes the same candidate harness files into both, runs
baseline then candidate with matching seeds, collects JSON and service logs,
and invokes the comparator:

```powershell
uv run --locked python tools/run_performance_comparison.py `
    --baseline-ref c29071e `
    --candidate-ref HEAD `
    --harness-ref HEAD `
    --profile smoke `
    --repetitions 3 `
    --max-regression 0.10 `
    --output-dir performance-artifacts
```

The currently implemented target is `managed-disposable` with environment
`local-disposable`. Remote deployment orchestration is intentionally absent
until project owners confirm a deployment interface, performance environment,
runner label, and Secret names. Extra non-secret load options can be supplied
as repeated `--load-arg=<token>` values. Credential options are rejected.

## Manual GitHub workflow

`.github/workflows/performance.yml` runs only through `workflow_dispatch`; it is
not part of push or pull-request pytest. It requires baseline/candidate refs,
profile, target/environment, repetition count, regression threshold, and a
project-owner supplied label for a fixed self-hosted performance runner.

The workflow does not contain a real address, credential, guessed Secret name,
or guessed project-specific runner label. It currently invokes only the local
disposable orchestrator. A plain `self-hosted` label is rejected: use an
otherwise-idle, fixed machine with controlled power, CPU, memory, network, and
storage conditions. Do not turn fluctuating GitHub-hosted results into a strict
performance gate. The workflow uploads raw JSON, comparison/manifest files,
harness logs, and server logs even when the comparison fails.
