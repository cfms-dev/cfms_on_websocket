# Performance testing

The performance harness is a black-box WebSocket client kept in this repository
so that its CFMS protocol implementation changes with the server. The harness
may run on a different host from the system under test; keeping the source in
the same repository does not imply colocating the load generator and server.

Real load runs use `tests.stress.ws_load` directly. Pytest covers the harness's
statistics, scheduling, configuration, and safety behavior but does not execute
long-running load scenarios.

## Remote runs

Remote mode is selected by passing `--host` or `--port`. Authenticated scenarios
take the username from `--username` or `CFMS_LOAD_USERNAME` and read the password
from an environment variable. The default password variable is
`CFMS_LOAD_PASSWORD`; `--password-env` can select another variable without
placing the secret in process arguments or result files.

PowerShell example:

```powershell
$env:CFMS_LOAD_USERNAME = "load-test-user"
$env:CFMS_LOAD_PASSWORD = Read-Host "Load-test password"

uv run --locked python -m tests.stress.ws_load `
    --host cfms-perf.example.internal --port 5104 `
    --scenario mixed --users 16 --duration 300 --ramp-up 30 `
    --rate 100 --seed 20260908 --json
```

Remote TLS connections verify the server certificate and hostname by default.
Use `--tls-ca-file` for a private CA. `--insecure` is available only for an
explicit disposable test target and must not be used for production-like runs.
Use `--no-ssl` only on an isolated trusted network.

The target must contain disposable accounts and data intended for performance
testing. Upload and mixed scenarios create persistent documents or directories.
Do not point them at a production database.

## Managed local runs

Managed mode starts the server from the current worktree and uses its generated
administrator credential. It requires `--managed-reset` because it deletes
`src/app.db`, `src/content/files`, and other runtime state. Run it only in a
disposable worktree:

```powershell
uv run --locked python -m tests.stress.ws_load `
    --scenario server-info --users 8 --duration 30 `
    --managed-reset --json
```

Managed mode permits the disposable server's self-signed certificate. This
exception does not apply to remote mode.

## Load models and results

Without `--rate`, every virtual user starts its next iteration after the prior
one completes. This closed model measures maximum throughput for the chosen
number of users.

With `--rate`, starts are scheduled at a fixed global rate and spread across the
configured users. A busy user skips schedule slots it cannot service instead of
silently lowering the requested rate. These slots are reported as
`dropped_iterations`; any non-zero value means the generator did not sustain the
requested arrival rate with the configured user count.

`--ramp-up` gradually activates users, and `--seed` makes the action selection in
mixed scenarios repeatable. Connection and login setup complete before measured
time begins.

The top-level request count, throughput, latency, and success rate describe
complete scenario iterations. `actions` contains the same metrics for each CFMS
action. For upload scenarios, one top-level iteration covers document creation
through upload acknowledgement, while `create_document` and `upload_file` remain
separately visible under `actions`.

Keep the harness commit, scenario parameters, raw JSON, server logs, target
configuration, and host resource metrics together for every retained run. Use
the same harness commit against baseline and candidate servers.
