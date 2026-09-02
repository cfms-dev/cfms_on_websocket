# Scheduled-task infrastructure

The optional `scheduling` extension provides durable schedule management and
execution. It does not register file, account, lockdown, or other business tasks;
core code and trusted extensions register those task types explicitly when they
are implemented.

## Installation and configuration

For a single server process without Redis:

```powershell
uv sync --extra ext-scheduling
```

```toml
[extensions]
enabled = ["scheduling"]

[provider]
scheduling = "local"
```

The local Provider embeds one scheduler thread and the configured number of
worker threads in the WebSocket server. Schedule definitions, pending executions,
leases, retries, and results are stored in the application database. A stopped
server therefore does not lose schedules; eligible missed occurrences are
coalesced when the server starts again.

This is the complete single-instance deployment: start CFMS normally. Do not run
`cfms-jobs`, and do not deploy Redis merely for scheduling. The server runtime
lock still enforces one WebSocket process for the configured runtime root.

For a distributed deployment:

```powershell
uv sync --extra ext-scheduling-cluster
```

Set `provider.scheduling = "redis"`, configure `[redis]`, and use a shared MySQL
or PostgreSQL application database. SQLite is intentionally rejected for this
mode. Start the WebSocket server plus one or more candidates and workers:

```bash
uv run cfms-jobs scheduler --server-root /srv/cfms/src
uv run cfms-jobs worker --server-root /srv/cfms/src
```

Every scheduler process is a candidate. A Redis lease with compare-and-renew and
compare-and-delete semantics elects one active scheduler. Redis Pub/Sub reduces
change latency, while periodic SQL reconciliation remains authoritative if a
notification is lost. Dramatiq transports execution IDs; workers revalidate the
database generation, task contract, payload, and execution lease before running.

Redis outages leave the WebSocket server running in a degraded state. Scheduling
management actions return 503 until Redis recovers. Scheduler and worker processes
retry their infrastructure connections; the server never silently falls back to
the local Provider.

Run one or more scheduler candidates and one or more workers under the platform's
service manager. Windows paths are accepted by `--server-root` as well. All jobs
processes hold a shared jobs runtime lock; release deployment, rollback, and
recovery take an exclusive lock and therefore refuse to proceed until every jobs
process has stopped. Stop the WebSocket server and all jobs services before those
operations.

## Task registration

Trusted extensions implement `ext_register_scheduled_tasks()` and return immutable
`ScheduledTaskRegistration` values. Names use `<extension_id>.<task_name>` and
payloads use a strict Pydantic model. Arbitrary import paths are never persisted or
executed.

```python
from pydantic import BaseModel

from include.domains.access.permissions import Permissions
from include.extensions.manager import hookimpl
from include.scheduling import ScheduledTaskRegistration


class CleanupPayload(BaseModel):
    folder_id: str


def run_cleanup(context, payload):
    # Use context.execution_id as the idempotency key for external effects.
    ...


@hookimpl
def ext_register_scheduled_tasks():
    return (
        ScheduledTaskRegistration(
            name="example.cleanup",
            contract_version=1,
            payload_model=CleanupPayload,
            execute=run_cleanup,
            required_permission=Permissions.PURGE,
        ),
    )
```

Execution is at-least-once. A process may finish an external effect and stop before
the database records success, so every task must make repeated use of the same
`context.execution_id` safe. Tasks run as system work rather than impersonating the
user who created the schedule. Authorization is checked when a schedule is created,
updated, or re-enabled.

## Trigger and execution semantics

- `cron` accepts a standard five-field crontab expression and an IANA timezone.
- `date` accepts an ISO 8601 timestamp containing a UTC offset.
- `interval` accepts positive whole seconds plus an offset-aware `start_at` anchor.
- Absolute timestamps are stored as UTC Unix seconds; the original timezone remains
  part of the schedule definition.
- Missed occurrences outside `misfire_grace_seconds` are skipped. Eligible missed
  occurrences coalesce to the latest one.
- One schedule has at most one active execution. Occurrences arriving while it runs
  coalesce into one latest pending execution.
- Each attempt owns a renewable database lease. Crashed work is reclaimable after
  expiry and uses the same deterministic execution ID.
- Completed execution history older than `history_retention_days` is removed in
  bounded hourly batches by the active scheduler.
- A one-time schedule becomes `completed` after success and `failed` after its final
  failed attempt. Failure of one recurring occurrence does not disable the schedule.

Provider changes require a full stop and restart. The database increments a Provider
generation, makes unfinished executions deliverable by the new Provider, and rejects
stale Redis messages. Startup refuses the switch while an unexpired execution lease
exists.

## WebSocket management actions

Protocol version 26 adds:

- `list_scheduled_task_types`
- `create_schedule`
- `get_schedule`
- `list_schedules`
- `update_schedule`
- `delete_schedule`

Reading requires `view_schedules`. Mutations require `manage_schedules`; creation and
updates also require the permission declared by the selected task type. Updates and
deletes require the current positive `revision` and return 409 for stale or active
conflicts. Deletion is logical, cancels future occurrences, and does not interrupt a
task already running.
