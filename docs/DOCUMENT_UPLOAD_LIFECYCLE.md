# Document Upload Lifecycle

CFMS treats a `FileTask` as a capability for transferring one file. It does not
store a document or revision owner on the task. When a document or revision is
deleted, the server instead checks whether the file remains reachable from any
active document, user avatar, or extension-owned non-cascading foreign key.
Only tasks for files that become unreachable are cancelled.

This resource-reachability rule is important for deduplicated files: deleting
one document does not interrupt a transfer that is still useful to another live
entity. Deleting the final live reference cancels every pending or active task
for that file. The same cancellation behavior applies to recursive directory
deletion, successful members of a partial (`207`) deletion, revision deletion,
and system lockdown.

## Task states

| Value | Name | Meaning |
| --- | --- | --- |
| `0` | `PENDING` | Available to be claimed, or resumable after a disconnect. |
| `1` | `COMPLETED` | Transfer and final database transition succeeded. |
| `2` | `CANCELLED` | Revoked because its file became unreachable or lockdown began. |
| `3` | `IN_PROGRESS` | Atomically claimed by one transfer connection. |
| `4` | `EXPIRED` | Its start or hard deadline elapsed. |

Claims use a conditional `PENDING -> IN_PROGRESS` update. Completion similarly
requires `IN_PROGRESS -> COMPLETED`, so duplicate claims and concurrent
cancellation, expiry, or completion cannot all win. A disconnected upload or
resumable download returns to `PENDING` only while its hard deadline remains;
cancelled and expired tasks never return to a live state.

## Upload deadlines and cleanup

For a newly created upload, `task_data.end_time` is the deadline for starting
the transfer. The first successful claim atomically resets `start_time` and sets
`end_time` to the hard transfer deadline. By default this gives the client one
hour to start and 24 hours to finish. While connected, five minutes without an
incoming frame aborts the stream; the task can be reclaimed if its hard deadline
has not passed.

The background lifecycle service runs immediately at startup and then at the
configured cleanup interval. It conditionally claims overdue tasks so multiple
instances cannot perform the same cleanup. For an abandoned later revision, it
removes only that inactive revision and repairs `current_revision`. If a
document has never acquired an active revision, it permanently purges the empty
document shell and releases the name. Deferred storage cleanup runs only after
the database transaction commits.

Calling `upload_document` repeatedly does not refresh a lease. An existing
pending upload task is returned unchanged, and an upload already in progress is
reported as a conflict. At most one non-terminal upload revision is retained for
a document.

## Limits and client responses

Each creator may hold at most 16 empty documents with live uploads by default.
Document creation also uses persistent, cross-instance fixed windows: 300
requests per account and 1000 per source IP in ten minutes. The account counter
serializes the reservation-count check with creation, preventing concurrent
requests from crossing the creator limit.

Protocol version 18 adds these responses:

- `410`: a cancelled or expired task, with `data.task_status` set to
  `cancelled` or `expired`.
- `409`: an upload is already active, with `data.task_status` set to
  `in_progress`.
- `429`: document creation was limited, with `data.scope` (`account`, `ip`, or
  `pending_documents`), `data.limit`, and `data.retry_after_seconds`.

Clients should discard cancelled or expired task credentials. For `409`, they
should let the existing stream finish or disconnect before retrying. For `429`,
they should wait at least `retry_after_seconds`; completing, deleting, or letting
an empty document expire also releases reservation capacity.

## Configuration

All settings are hot-reloaded from `[document.upload]`:

```toml
[document.upload]
start_timeout_seconds = 3600
max_duration_seconds = 86400
idle_timeout_seconds = 300
cleanup_interval_seconds = 60
max_pending_documents_per_creator = 16
creation_rate_window_seconds = 600
creation_rate_per_user = 300
creation_rate_per_ip = 1000
```

Use shorter start deadlines and lower reservation caps when names are scarce or
abuse is common. Increase the hard deadline for reliably authenticated users
who upload large files over slow links. Keep the idle timeout long enough for
normal network jitter, and keep cleanup frequent enough that expired names are
released promptly without creating excessive database work.

On upgrade, existing pending uploads receive a 24-hour grace period, so old
reservations are not removed immediately. The migration adds a status check
constraint and the persistent creation-throttle table. Back up the database and
run `uv run alembic upgrade head`; downgrade removes the new constraint and
throttle table but cannot recreate content already purged by expiry.

The design follows established resumable-upload expiry and termination
patterns: [tus expiration and termination](https://tus.io/protocols/resumable-upload),
[Google Cloud resumable upload sessions](https://docs.cloud.google.com/storage/docs/resumable-uploads),
[Amazon S3 incomplete multipart upload cleanup](https://docs.aws.amazon.com/AmazonS3/latest/userguide/mpu-abort-incomplete-mpu-lifecycle-config.html),
and [OWASP resource-consumption guidance](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/).
