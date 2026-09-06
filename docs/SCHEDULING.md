# Scheduled-task infrastructure

Durable scheduling is always-on core infrastructure. Core code and trusted
extensions register task types, and the configured scheduling Provider starts
whether or not the `scheduling` extension is enabled. The extension controls only
the six WebSocket query and configuration actions and its extension flag; disabling
it does not pause or delete system schedules or previously persisted user schedules.

The core and built-in extensions register hidden system schedules for execution
history, expired permissions, abandoned uploads, authentication throttle records,
and document creation/download risk state. The scheduler creates and reconciles
these schedules from current configuration. System schedules have no user owner,
are not returned by the management API, and cannot be created, changed, or deleted
through that API.

## Installation and configuration

For a single server process without Redis, the normal core installation is
sufficient:

```toml
[extensions]
# Optional: expose the scheduling management API.
enabled = ["scheduling"]

[provider]
scheduling = "local"
```

The local Provider embeds one scheduler thread and the configured number of
worker threads in the WebSocket server. Schedule definitions, pending executions,
leases, retries, and results are stored in the application database. A stopped
server therefore does not lose schedules; eligible missed occurrences are
coalesced when the server starts again.

This is the complete single-instance deployment: start CFMS normally. No auxiliary
scheduler or worker service is required, and Redis should not be deployed merely
for scheduling. The server runtime lock still enforces one WebSocket process for
the configured runtime root.

For a distributed deployment:

```powershell
uv sync --extra ext-scheduling-cluster
```

Set `provider.scheduling = "redis"`, configure `[redis]`, and use a shared MySQL
or PostgreSQL application database. SQLite is intentionally rejected for this
mode. Start CFMS normally on every application node; no separate scheduled-task
processes are used.

Every WebSocket server embeds one scheduler candidate and a Dramatiq worker pool
containing `scheduling.worker_threads` threads. A Redis lease with
compare-and-renew and compare-and-delete semantics elects one active scheduler
across the cluster. Total worker capacity therefore grows with the number of CFMS
server instances. Redis Pub/Sub reduces change latency, while periodic SQL
reconciliation remains authoritative if a notification is lost. Dramatiq
transports execution IDs; workers revalidate the database generation, task
contract, payload, and execution lease before running.

Redis outages leave the WebSocket server running in a degraded state. Scheduling
management actions return 503 until Redis recovers. The Provider retries its
infrastructure connections; the server never silently falls back to the local
Provider.

The runtime lock prevents deployment, rollback, or recovery while the server using
that runtime root is active. In a distributed deployment, stop every CFMS server
that shares the application database before changing the scheduling Provider,
running database migrations, or switching releases.

## Task registration

Trusted extensions implement `ext_register_scheduled_tasks()` and return immutable
`ScheduledTaskRegistration` values. Core registrations are installed first, then
registrations from every loaded extension are merged; duplicate names fail startup.
Names use `<owner>.<task>` (for example `core`, `builtin`, or an extension owner) and
payloads use a strict Pydantic model. Arbitrary import paths are never persisted or
executed.

An internal task may set `user_schedulable=False` and provide a
`system_schedule` factory returning `SystemScheduleDefinition`. The active
scheduler treats that definition as desired state, preserves the interval anchor,
and updates the persisted schedule when its configuration changes. An immediate
execution requested by the definition is queued separately from the trigger's next
run, so reconciliation does not shift the anchored cadence. Removing the
registration disables its system schedule. Do not use this mechanism for
event-driven queues such as file deduplication.

User-configurable tasks must declare `required_permission`. Pure system tasks may
omit it because they are never offered to users. A persisted user schedule remains
active while the management extension is disabled; if its owning extension is not
loaded or its contract version no longer matches, execution reports registration
unavailable under the normal contract rules.

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
  bounded hourly batches by the hidden `core.schedule_history_cleanup` task.
- A one-time schedule becomes `completed` after success and `failed` after its final
  failed attempt. Failure of one recurring occurrence does not disable the schedule.
- Updating a completed or failed schedule reactivates it with a newly calculated
  next run; the `enabled` flag continues to control whether it is dispatched.
- Retiring a schedule cancels pending and retrying work without interrupting an
  execution that is already running.

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

These actions are registered only when the `scheduling` extension is enabled. They
expose only user-managed schedules and task types. System-managed
maintenance remains observable through execution logs and audit records rather
than through mutable schedule resources.

Reading requires `view_schedules`. Mutations require `manage_schedules`; creation and
updates also require the permission declared by the selected task type. Updates and
deletes require the current positive `revision` and return 409 for stale or active
conflicts. Deletion is logical, cancels future occurrences, and does not interrupt a
task already running.
