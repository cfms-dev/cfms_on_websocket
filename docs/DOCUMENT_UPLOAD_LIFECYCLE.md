# Document Upload Lifecycle

CFMS treats a `FileTask` as a capability for transferring one file. A download
task records the account that issued it for risk attribution, but that field is
not ownership or an authentication binding: possession of the task credential
is still sufficient to use or resume the download. When a document or revision
is deleted, the server instead checks whether the file remains reachable from
any active document, user avatar, or extension-owned non-cascading foreign key.
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
invokes the transactional upload hook. The `builtin` extension uses that hook
to persist a deduplication task in the same transaction. The task is initially
held for five minutes so the remaining extension upload hooks can run first.
After the server sends the successful upload response, a response hook lets
`builtin` release the task immediately; if the process exits first, the recovery
deadline makes the task eligible without client intervention.

The `builtin` extension starts one deduplication worker per server instance and
stops it through the normal extension lifecycle. Workers use database leases and
compare-and-set claims, so SQLite and clustered database deployments share the
same recovery behavior. The oldest active file by `(created_time, id)` is the
canonical copy. Reference migration commits before the duplicate object is
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

## Upload performance regression checks

Use the WebSocket load tool's `upload-unique` and `upload-duplicate` scenarios
to compare the same upload harness against two revisions. `upload-unique`
generates a different payload for every document, so it is the primary guard
for uploads that do not need reference merging. The reported latency covers the
file-transfer request through the server's success confirmation. Throughput is
measured across the whole create-and-upload loop.

Run benchmarks only in disposable worktrees. Managed mode requires
`--managed-reset` because every run deletes `src/app.db` and
`src/content/files`. The following PowerShell example compares the revision
immediately before deferred deduplication (`42b2044`) with the candidate. It
copies the candidate's benchmark harness into the baseline worktree so client
and measurement code remain identical.

```powershell
$repo = (Get-Location).Path
$parent = Split-Path $repo
$baseline = Join-Path $parent "cfms-perf-baseline"
$candidate = Join-Path $parent "cfms-perf-candidate"
$results = Join-Path $parent "cfms-perf-results"

git worktree add --detach $baseline 42b2044
git worktree add --detach $candidate HEAD
Copy-Item -LiteralPath "$candidate\tests\stress\ws_load.py" `
    -Destination "$baseline\tests\stress\ws_load.py" -Force
New-Item -ItemType Directory -Force -Path "$results\baseline", `
    "$results\candidate" | Out-Null

foreach ($entry in @(
    @{ Name = "baseline"; Path = $baseline },
    @{ Name = "candidate"; Path = $candidate }
)) {
    Push-Location $entry.Path
    uv sync --locked --dev
    foreach ($scenario in "upload-unique", "upload-duplicate") {
        1..5 | ForEach-Object {
            uv run --locked python -m tests.stress.ws_load `
                --scenario $scenario --users 8 --duration 30 `
                --payload-size 1048576 --managed-reset --json |
                Set-Content -Encoding utf8 `
                    "$results\$($entry.Name)\$scenario-$_.json"
        }
    }
    Pop-Location
}

uv run --locked python tools/compare_upload_benchmarks.py `
    "$results\baseline" "$results\candidate" --max-regression 0.10
```

The comparator uses the median throughput and median p95 across repeated runs,
requires matching parameters, requires `upload-unique` results, and exits with
status 1 if success rate drops or either throughput or p95 regresses beyond the
chosen threshold. Run on the same otherwise-idle host, keep power and storage
conditions fixed, and inspect both raw JSON and server logs before accepting a
result. Add worktrees for intermediate commits when the first comparison finds
a regression and the introducing commit needs to be isolated.

## Limits and client responses

Protocol version 25 replaces ambiguous file-task claim failures with a dedicated
conclusion-code namespace:

| Code | Meaning | Client action |
| --- | --- | --- |
| `46000` | The task credential is invalid or cannot be used for this request. | Discard it and obtain a new task. |
| `46001` | Another connection is processing the task. | Wait for that connection to finish or disconnect before retrying. |
| `46002` | The task is already completed. | Obtain a new task if another transfer is needed. |
| `46003` | The task is cancelled. | Do not retry it. |
| `46004` | The task is expired. | Obtain a new task. |
| `46005` | The claim conflicted with another state transition. | Retry with bounded backoff. |

Codes `46001` through `46004` include `data.task_status` and all six responses
include `data.retryable`. Code `46000` deliberately combines an unknown task,
a transfer-mode mismatch, and a task whose start time has not arrived. Responses
never expose the expected mode, task timing, file identity or path, issuer, or
the database condition that rejected a claim.

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

Protocol version 18 added these responses:

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

## Download risk controls

Protocol version 19 applies a separate adaptive policy to downloads at two
boundaries:

- `get_document` and `get_revision` consume task-issuance tokens for the
  authenticated account and effective source IP after access checks succeed.
- `download_file` first validates and claims the bearer task, then consumes
  transfer-start tokens for the issuing account (when it still exists), the
  current source IP, and the individual task. A denied start atomically returns
  the task to `PENDING`, so it can be retried within its existing deadline.

Invalid task credentials do not consume tokens. Existing tasks without issuer
attribution remain valid and use only the current IP and task buckets. A task's
issuer is used for account risk and the bypass permission; it does not restrict
who may present the bearer credential.

Account and IP risk uses account age, recent account fanout from the source IP,
and recent denials. One signal selects elevated risk; a high threshold or two
signals select high risk. Normal, elevated, and high requests cost one, three,
and ten account/IP tokens by default. Every transfer start or resume consumes
one task token regardless of risk. The default task bucket permits a burst of
five starts and refills ten starts per hour.

Download limiting defaults to `observe`: the server maintains shadow buckets
and logs decisions but does not reject task issuance or transfer starts. In
`enforce` mode, a rejection returns `429` with `data.scope` (`account`, `ip`, or
`task`), `data.limit`, and `data.retry_after_seconds`. Risk levels and reasons
remain server-only. Users with `bypass_document_download_rate_limit` skip
download token consumption; new installations and upgrades grant this
permission to `sysop` by default.

Transfer-start logs include remaining bytes and the current number of active
downloads. These values are observability signals only: the policy does not
charge per byte, shape bandwidth continuously, or impose a hard concurrency
cap.

## File chunk negotiation and transfer resume

Uploads and downloads use the same initial chunk-size selection rule: the
server chooses the smallest of the client's maximum, `[server].file_chunk_size`,
and the direction's hard limit. Protocol version 21 requires upload requests to
include `task_id`, `file_size`, `sha256`, and `max_chunk_size`; `restart` is an
optional boolean. The upload maximum must be at least 512 bytes. The server
returns a `transfer_file` process frame containing `file_size`, `chunk_size`,
the authoritative resume `offset`, and whether this upload is resumable. Clients
seek to that offset and start sending chunks without another ready exchange.

The negotiated size is stored in the common `FileTask.chunk_size` field and
never changes for that task. A client maximum smaller than the stored size
produces `409` with `data.chunk_size`. Non-empty uploads with a valid SHA-256
retain progress after disconnects and idle timeouts. File size and digest must
match the stored upload metadata; a mismatch returns `409` without changing the
checkpoint. Retrying with `restart = true` explicitly discards the checkpoint
and replaces the metadata while retaining the negotiated chunk size. Uploads
without a digest remain supported but restart at offset zero after interruption.

Local storage resumes at the last complete protocol chunk. S3 storage persists
multipart upload IDs together with the authoritative part numbers and ETags
returned by each successful upload request. `ListParts` verifies that the
session still exists but is never used as the completion manifest. The S3 part
size is aligned to the negotiated chunk size, is at least 5 MiB, and grows for
large objects so no upload exceeds 10,000 parts. Consequently an interrupted S3
transfer may retransmit the uncommitted tail of one part. Deployments using S3
must allow create, upload, list-parts, complete, and abort multipart operations;
an S3 lifecycle rule that aborts old incomplete multipart uploads is also
recommended. An active S3 session created before authoritative manifests were
persisted restarts from offset zero and overwrites its unrecorded parts.

Every `download_file.data` object must include
`max_chunk_size` in the inclusive range 16 KiB through 2 MiB. The server chooses
the result using the shared rule with a 2 MiB download hard limit, stores it on
the `FileTask`, and returns it as `transfer_file.data.chunk_size` together with
`file_size` and `total_chunks`.

An initial request uses `offset = 0`. A resume request uses the byte offset of
the next complete, durably stored chunk. Once a task has a negotiated chunk
size, every later attempt retains it, including retries from offset zero after
a configuration change. Non-zero offsets must be aligned to the stored size. A
client maximum smaller than the stored size produces a `409` response containing
`data.chunk_size`, and the task is released so a compatible client can retry.
The file-size offset is also accepted, allowing a client that has all encrypted
chunks but missed the final key frame to resume without downloading the chunks
again.

The AES key is a process frame. After decrypting and verifying
the destination, the client sends `complete`; only then does the server mark
the task complete and conclude the stream with `transfer_complete`. A disconnect
before that acknowledgement releases the task and retains its key and chunk
size for a safe resume.

The common database column is nullable for tasks created before the migration.
Their size is established on the first post-upgrade transfer or resume and then
remains fixed.

## Configuration

Upload settings are hot-reloaded from `[document.upload]`:

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

Download risk settings are independently hot-reloaded from
`[document.download.risk_control]`:

```toml
[document.download.risk_control]
mode = "observe"
refill_period_seconds = 600
issue_account_capacity = 60
issue_account_refill_tokens = 300
issue_ip_capacity = 200
issue_ip_refill_tokens = 1000
transfer_account_capacity = 60
transfer_account_refill_tokens = 300
transfer_ip_capacity = 200
transfer_ip_refill_tokens = 1000
task_capacity = 5
task_refill_tokens = 10
task_refill_period_seconds = 3600
new_account_seconds = 604800
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

Keep `mode = "observe"` before enforcing a new policy in production. Observe
mode maintains the same shadow buckets and denial history and logs
`risk_level`, `risk_reasons`, and `would_block`, but allows requests that would
be rejected only by the corresponding rate policy. The pending-document hard
limit is still enforced. Review elevated/high decisions and `would_block`
events, adjust the thresholds if necessary, and then hot-reload
`mode = "enforce"`. Switching modes does not clear accumulated bucket state.

`document.upload.creation_risk_control` is the only active configuration
interface for document-creation rate policy. If the table is omitted, the
adaptive policy uses the defaults shown above.

On upgrade, existing pending uploads and downloads retain their original
lifecycle. Back up the database and run `uv run alembic upgrade head`. The
migrations move existing document-creation bucket and IP/account state into
shared namespaced tables, add download-task issuer attribution, and grant the
download rate-bypass permission to an existing `sysop` group. Existing adaptive
document-creation state is preserved under the `document_creation` namespace.

Risk-control tables are transient and excluded from backups. Downgrading the
shared tables restores only the document-creation namespace to the previous
schema and discards download state. To roll back enforcement without
downgrading, use observe mode.

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
