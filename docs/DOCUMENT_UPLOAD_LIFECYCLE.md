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

Task deadlines are enforced whenever a task is claimed and while an active
transfer is running. This makes the hard transfer deadline part of the task
state machine instead of depending on a periodic background thread.

Abandoned upload resources are reclaimed separately. The server performs one
sweep at startup, targets the affected document or name before creating another
upload reservation, and opportunistically processes a bounded batch at the
configured cleanup interval when document upload requests arrive. A task that
has already been marked `EXPIRED` remains eligible for this later reclamation.
For an abandoned later revision, cleanup removes only that inactive revision
and repairs `current_revision`. If a document has never acquired an active
revision, it permanently purges the empty document shell and releases the name.
Deferred storage cleanup runs only after the database transaction commits.

## Deferred file deduplication

For non-empty uploads with a verified SHA-256 digest, upload completion also
persists a deduplication task in the same transaction. The task is initially
held for five minutes so extension upload hooks can run first. After the server
sends the successful upload response, it releases the task immediately; if the
process exits first, the recovery deadline makes the task eligible without
client intervention.

Each server instance runs one deduplication worker. Workers use database leases
and compare-and-set claims, so SQLite and clustered database deployments share
the same recovery behavior. The oldest active file by `(created_time, id)` is
the canonical copy. Reference migration commits before the duplicate object is
removed from storage. Pending downloads are redirected to the canonical file,
while an already-running download keeps the inactive source file alive until
the transfer ends.

Merge and storage failures are retried with bounded exponential backoff. A
crash after reference migration resumes at storage deletion, and deleting an
already-missing object is treated as success. Consequently, upload success
means the verified file is readable; it does not promise that redundant
storage has already been reclaimed. Worker logs include source and canonical
IDs, retry delays, lease recovery, and storage cleanup failures. Upgrades do
not enqueue historical files automatically.

Calling `upload_document` repeatedly does not refresh a lease. An existing
pending upload task is returned unchanged, and an upload already in progress is
reported as a conflict. At most one non-terminal upload revision is retained for
a document.

## Limits and client responses

Each creator may hold at most 16 empty documents with live uploads by default.
Document creation also uses persistent, cross-instance token buckets for the
account and source IP. At normal risk, the buckets refill at 300 requests per
account and 1000 per IP every ten minutes, with burst capacities of 60 and 200.
Elevated-risk requests cost three tokens and high-risk requests cost ten, giving
effective account rates of approximately 100 and 30 requests per ten minutes.

Risk classification uses account age, the creator's pending-document ratio,
the number of accounts recently seen on the source IP, and recent rate denials.
One elevated signal selects elevated risk. A high threshold or two elevated
signals select high risk. The exact thresholds are configurable and are
evaluated again for every request. Trusted-proxy handling and IP normalization
are applied before the IP signal is recorded.

The account bucket also serializes the reservation-count check with creation,
preventing concurrent requests from crossing the creator limit. Users with the
`bypass_document_creation_rate_limit` permission skip risk scoring and token
consumption, but still acquire that account lock and remain subject to the
pending-document hard limit. New installations and upgrades grant this
permission to the `sysop` group by default.

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

For account or IP responses, `limit` is the effective number of requests per
configured refill period at the request's risk level. Risk levels and reasons
are intentionally omitted from client responses and are emitted only in the
server's structured logs.

## Configuration

All settings are hot-reloaded from `[document.upload]`:

```toml
[document.upload]
start_timeout_seconds = 3600
max_duration_seconds = 86400
idle_timeout_seconds = 300
cleanup_interval_seconds = 60
max_pending_documents_per_creator = 16

[document.upload.creation_risk_control]
mode = "enforce"
refill_period_seconds = 600
account_capacity = 60
account_refill_tokens = 300
ip_capacity = 200
ip_refill_tokens = 1000
new_account_seconds = 604800
pending_elevated_ratio = 0.5
pending_high_ratio = 0.75
ip_account_window_seconds = 600
ip_accounts_elevated = 4
ip_accounts_high = 10
denial_window_seconds = 600
denials_elevated = 1
denials_high = 3
elevated_cost = 3
high_cost = 10
state_retention_seconds = 86400
```

Use shorter start deadlines and lower reservation caps when names are scarce or
abuse is common. Increase the hard deadline for reliably authenticated users
who upload large files over slow links. Keep the idle timeout long enough for
normal network jitter. Cleanup of the document or name being accessed is not
delayed; the interval controls bounded opportunistic sweeps of unrelated
expired uploads and the minimum interval between stale risk-state cleanups.

Set `mode = "observe"` before enforcing a new policy in production. Observe
mode maintains the same shadow buckets and denial history and logs
`risk_level`, `risk_reasons`, and `would_block`, but allows requests that would
be rejected only by the rate policy. The pending-document hard limit is still
enforced. Review elevated/high decisions and `would_block` events, adjust the
thresholds if necessary, and then hot-reload `mode = "enforce"`. Switching modes
does not clear accumulated bucket state.

`document.upload.creation_risk_control` is the only active configuration
interface for document-creation rate policy. If the table is omitted, the
adaptive policy uses the defaults shown above.

On upgrade, existing pending uploads retain their original lifecycle. Back up
the database and run `uv run alembic upgrade head`. The migration grants the
rate-bypass permission to an existing `sysop` group, replaces fixed-window
counters with empty token buckets, and creates the rolling IP/account signal
table. The old counters cannot be reliably converted because deployments may
use different limits, so their transient state is intentionally reset.

Risk-control tables are transient and excluded from backups. Downgrade removes
their state and recreates an empty fixed-window table; it cannot reconstruct old
counter values. To roll back enforcement without downgrading, use observe mode.

The design follows established resumable-upload expiry and termination
patterns: [tus expiration and termination](https://tus.io/protocols/resumable-upload),
[Google Cloud resumable upload sessions](https://docs.cloud.google.com/storage/docs/resumable-uploads),
[Amazon S3 incomplete multipart upload cleanup](https://docs.aws.amazon.com/AmazonS3/latest/userguide/mpu-abort-incomplete-mpu-lifecycle-config.html),
and [OWASP resource-consumption guidance](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/).
The adaptive rate policy also follows the multi-dimensional aggregation and
staged-enforcement patterns documented by
[AWS WAF](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based.html),
[Cloudflare](https://developers.cloudflare.com/waf/rate-limiting-rules/), and
[Redis token-bucket guidance](https://redis.io/docs/latest/develop/use-cases/rate-limiter/).
