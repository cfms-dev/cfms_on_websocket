import datetime as dt
import hashlib
import threading
import time
from dataclasses import dataclass
from typing import cast

import orjson
from loguru import logger
from sqlalchemy import CursorResult, and_, delete, or_, select, update
from sqlalchemy.dialects.mysql import insert as mysql_insert
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from include.config.validation import SchedulingPolicy
from include.database.models.scheduling import (
    Schedule,
    ScheduleExecution,
    SchedulingRuntimeState,
)
from include.database.session import Session
from include.domains.operations.commands.audit import log_audit
from include.scheduling.commands import cancel_unstarted_schedule_execution
from include.scheduling.contracts import ScheduledTaskContext
from include.scheduling.registry import ScheduledTaskRegistry
from include.scheduling.triggers import advance_trigger, build_trigger, first_run_at


@dataclass(frozen=True, slots=True)
class ClaimedExecution:
    id: str
    schedule_id: str
    task_name: str
    task_contract_version: int
    payload: dict
    scheduled_for: float
    attempt: int
    lease_owner: str


def execution_id(schedule_id: str, scheduled_for: float) -> str:
    """Return the deterministic SHA-256 ID for one scheduled occurrence."""
    occurrence = round(scheduled_for * 1_000_000)
    return hashlib.sha256(f"{schedule_id}:{occurrence}".encode()).hexdigest()


def _build_runtime_state_upsert(
    dialect_name: str,
    provider: str,
    current_time: float,
):
    values = {
        "id": 1,
        "provider": provider,
        "generation": 1,
        "schema_version": 1,
        "updated_at": current_time,
    }
    if dialect_name == "sqlite":
        return (
            sqlite_insert(SchedulingRuntimeState)
            .values(**values)
            .on_conflict_do_nothing(index_elements=[SchedulingRuntimeState.id])
        )
    if dialect_name == "postgresql":
        return (
            postgresql_insert(SchedulingRuntimeState)
            .values(**values)
            .on_conflict_do_nothing(index_elements=[SchedulingRuntimeState.id])
        )
    if dialect_name == "mysql":
        return (
            mysql_insert(SchedulingRuntimeState)
            .values(**values)
            .on_duplicate_key_update(id=SchedulingRuntimeState.id)
        )
    raise ValueError(f"Unsupported database dialect: {dialect_name}")


def ensure_runtime_state(provider: str, now: float | None = None) -> int:
    """Ensure the active scheduling provider state exists and return its generation.

    If the provider changes, active execution leases prevent the switch; otherwise
    pending work is reset and moved to the new provider generation.
    """
    current_time = time.time() if now is None else now
    with Session() as session, session.begin():
        session.execute(
            _build_runtime_state_upsert(
                session.get_bind().dialect.name,
                provider,
                current_time,
            )
        )
        state = session.get(SchedulingRuntimeState, 1)
        assert state is not None
        if state.provider == provider:
            return state.generation

        active_execution = session.scalar(
            select(ScheduleExecution.id).where(
                ScheduleExecution.state == "running",
                ScheduleExecution.lease_expires_at > current_time,
            )
        )
        if active_execution is not None:
            raise RuntimeError(
                "Cannot switch scheduling provider while an execution lease is active"
            )

        state.provider = provider
        state.generation += 1
        state.updated_at = current_time
        session.execute(
            update(ScheduleExecution)
            .where(ScheduleExecution.state.in_(("pending", "running", "retry_wait")))
            .values(
                provider_generation=state.generation,
                state="pending",
                dispatch_state="pending",
                retry_at=None,
                lease_owner=None,
                lease_expires_at=None,
            )
        )
        return state.generation


def synchronize_system_schedules(
    registry: ScheduledTaskRegistry,
    *,
    now: float | None = None,
) -> int:
    """Reconcile registered system schedules with their persisted desired state.

    Missing registrations retire their schedules, while new or changed definitions
    are created or updated. The return value is the number of schedules changed.
    """
    current_time = time.time() if now is None else now
    # Validate and materialize every definition before opening the transaction so a
    # bad registration cannot leave the persisted desired state partly reconciled.
    desired: dict[str, tuple] = {}
    for registration in registry.all():
        if registration.system_schedule is None:
            continue
        definition = registration.system_schedule()
        if definition.id in desired:
            raise ValueError(f"Duplicate system schedule ID {definition.id!r}")
        payload = registry.validate_payload(
            registration.name,
            registration.contract_version,
            definition.payload,
        ).model_dump(mode="json")
        desired[definition.id] = (
            registration,
            definition,
            payload,
            dict(definition.trigger_data),
        )

    changed = 0
    with Session() as session, session.begin():
        orphaned = session.scalars(
            select(Schedule).where(
                Schedule.system_managed.is_(True),
                Schedule.id.not_in(desired),
                or_(Schedule.enabled.is_(True), Schedule.status != "deleted"),
            )
        ).all()
        for schedule in orphaned:
            schedule.enabled = False
            schedule.status = "deleted"
            schedule.next_run_at = None
            schedule.pending_scheduled_for = None
            schedule.revision += 1
            schedule.updated_at = current_time
            schedule.deleted_at = current_time
            cancel_unstarted_schedule_execution(
                session,
                schedule,
                now=current_time,
                reason="System schedule retired before execution started",
            )
            changed += 1

        for schedule_id, item in desired.items():
            registration, definition, payload, trigger_data = item
            schedule = session.get(Schedule, schedule_id)
            if schedule is not None and not schedule.system_managed:
                raise RuntimeError(
                    f"System schedule ID {schedule_id!r} is already user managed"
                )
            if definition.trigger_type == "interval" and "start_at" not in trigger_data:
                # Preserve the original interval anchor; deriving it from each poll
                # would silently shift the cadence whenever definitions reconcile.
                if (
                    schedule is not None
                    and schedule.trigger_type == "interval"
                    and "start_at" in schedule.trigger_data
                ):
                    trigger_data["start_at"] = schedule.trigger_data["start_at"]
                else:
                    trigger_data["start_at"] = dt.datetime.fromtimestamp(
                        current_time, dt.UTC
                    ).isoformat()
            trigger = build_trigger(
                definition.trigger_type,
                trigger_data,
                definition.timezone,
            )
            next_run_at = first_run_at(trigger, current_time)
            pending_scheduled_for = current_time if definition.run_immediately else None
            values = {
                "task_name": registration.name,
                "task_contract_version": registration.contract_version,
                "payload": payload,
                "trigger_type": definition.trigger_type,
                "trigger_data": trigger_data,
                "timezone": definition.timezone,
                "created_by": None,
                "updated_by": None,
            }
            if schedule is None:
                session.add(
                    Schedule(
                        id=schedule_id,
                        **values,
                        system_managed=True,
                        enabled=True,
                        status="active",
                        next_run_at=next_run_at,
                        pending_scheduled_for=pending_scheduled_for,
                        created_at=current_time,
                        updated_at=current_time,
                    )
                )
                changed += 1
                continue

            current = {
                "task_name": schedule.task_name,
                "task_contract_version": schedule.task_contract_version,
                "payload": schedule.payload,
                "trigger_type": schedule.trigger_type,
                "trigger_data": schedule.trigger_data,
                "timezone": schedule.timezone,
                "created_by": schedule.created_by,
                "updated_by": schedule.updated_by,
            }
            if current == values and schedule.enabled and schedule.status == "active":
                continue
            for name, value in values.items():
                setattr(schedule, name, value)
            schedule.enabled = True
            schedule.status = "active"
            schedule.next_run_at = next_run_at
            schedule.pending_scheduled_for = pending_scheduled_for
            schedule.revision += 1
            schedule.updated_at = current_time
            schedule.deleted_at = None
            changed += 1
    return changed


def _create_execution(
    session, schedule: Schedule, scheduled_for: float, generation: int
) -> ScheduleExecution:
    item = ScheduleExecution(
        id=execution_id(schedule.id, scheduled_for),
        schedule_id=schedule.id,
        provider_generation=generation,
        scheduled_for=scheduled_for,
    )
    session.add(item)
    schedule.active_execution_id = item.id
    return item


def _advance_schedule_if_current(
    session,
    schedule: Schedule,
    **values,
) -> bool:
    """Advance a schedule only if its observed aggregate state is unchanged."""
    advanced = cast(
        CursorResult,
        session.execute(
            update(Schedule)
            .where(
                Schedule.id == schedule.id,
                Schedule.revision == schedule.revision,
                Schedule.enabled.is_(True),
                Schedule.status == "active",
                Schedule.next_run_at == schedule.next_run_at,
                Schedule.pending_scheduled_for == schedule.pending_scheduled_for,
                Schedule.active_execution_id == schedule.active_execution_id,
            )
            .values(**values)
        ),
    )
    return advanced.rowcount == 1


def enqueue_due_schedules(
    generation: int,
    policy: SchedulingPolicy,
    *,
    now: float | None = None,
) -> int:
    """Create durable executions for schedules that are due.

    Eligible missed occurrences coalesce to the latest one. If a schedule already
    has an active execution, that occurrence is retained as its next pending run.
    """
    current_time = time.time() if now is None else now
    # The shortlist is intentionally advisory. Each candidate is rechecked in its
    # own transaction so concurrent schedule updates cannot enqueue stale work.
    with Session() as session:
        due_ids = session.scalars(
            select(Schedule.id)
            .where(
                Schedule.enabled.is_(True),
                Schedule.status == "active",
                or_(
                    Schedule.next_run_at <= current_time,
                    and_(
                        Schedule.active_execution_id.is_(None),
                        Schedule.pending_scheduled_for <= current_time,
                    ),
                ),
            )
            .order_by(
                Schedule.pending_scheduled_for,
                Schedule.next_run_at,
                Schedule.id,
            )
            .limit(policy.claim_batch_size)
        ).all()

    created = 0
    for schedule_id in due_ids:
        with Session() as session, session.begin():
            schedule = session.get(Schedule, schedule_id)
            if schedule is None or not schedule.enabled or schedule.status != "active":
                continue

            next_run_due = (
                schedule.next_run_at is not None
                and schedule.next_run_at <= current_time
            )
            pending_due = (
                schedule.pending_scheduled_for is not None
                and schedule.pending_scheduled_for <= current_time
            )
            if not next_run_due and not pending_due:
                continue

            next_run_at = schedule.next_run_at
            latest_due_at = schedule.pending_scheduled_for if pending_due else None
            if next_run_due:
                trigger = build_trigger(
                    schedule.trigger_type, schedule.trigger_data, schedule.timezone
                )
                advance = advance_trigger(
                    trigger,
                    schedule.next_run_at,
                    current_time,
                    policy.misfire_grace_seconds,
                )
                next_run_at = advance.next_run_at
                if advance.latest_due_at is not None and (
                    latest_due_at is None or advance.latest_due_at > latest_due_at
                ):
                    latest_due_at = advance.latest_due_at

            if latest_due_at is None:
                values = {"next_run_at": next_run_at}
                if next_run_at is None and schedule.active_execution_id is None:
                    values["status"] = "completed"
                if not _advance_schedule_if_current(session, schedule, **values):
                    session.rollback()
                continue
            if schedule.active_execution_id is not None:
                # A schedule exposes only one execution slot; repeated polls replace
                # the pending timestamp with the latest eligible occurrence.
                if not _advance_schedule_if_current(
                    session,
                    schedule,
                    next_run_at=next_run_at,
                    pending_scheduled_for=latest_due_at,
                ):
                    session.rollback()
                continue
            reserved_execution_id = execution_id(schedule.id, latest_due_at)
            if not _advance_schedule_if_current(
                session,
                schedule,
                next_run_at=next_run_at,
                pending_scheduled_for=None,
                active_execution_id=reserved_execution_id,
            ):
                session.rollback()
                continue
            _create_execution(session, schedule, latest_due_at, generation)
            created += 1
    return created


def claim_execution(
    generation: int,
    lease_owner: str,
    policy: SchedulingPolicy,
    *,
    now: float | None = None,
) -> ClaimedExecution | None:
    """Atomically lease the oldest runnable execution for a local worker.

    Return an immutable task snapshot, or ``None`` when no execution is available
    or another worker wins the claim.
    """
    current_time = time.time() if now is None else now
    with Session() as session, session.begin():
        candidate_id = session.scalar(
            select(ScheduleExecution.id)
            .where(
                ScheduleExecution.provider_generation == generation,
                ScheduleExecution.state.in_(("pending", "running", "retry_wait")),
                ScheduleExecution.schedule_id.in_(
                    select(Schedule.id).where(Schedule.status != "deleted")
                ),
                or_(
                    ScheduleExecution.retry_at.is_(None),
                    ScheduleExecution.retry_at <= current_time,
                ),
                or_(
                    ScheduleExecution.lease_expires_at.is_(None),
                    ScheduleExecution.lease_expires_at <= current_time,
                ),
            )
            .order_by(ScheduleExecution.created_at, ScheduleExecution.id)
            .limit(1)
        )
        if candidate_id is None:
            return None

        # The preceding SELECT only chooses a candidate. This conditional UPDATE is
        # the claim boundary that prevents two workers from owning the same lease.
        claimed = cast(
            CursorResult,
            session.execute(
                update(ScheduleExecution)
                .where(
                    ScheduleExecution.id == candidate_id,
                    ScheduleExecution.provider_generation == generation,
                    ScheduleExecution.state.in_(("pending", "running", "retry_wait")),
                    ScheduleExecution.schedule_id.in_(
                        select(Schedule.id).where(Schedule.status != "deleted")
                    ),
                    or_(
                        ScheduleExecution.retry_at.is_(None),
                        ScheduleExecution.retry_at <= current_time,
                    ),
                    or_(
                        ScheduleExecution.lease_expires_at.is_(None),
                        ScheduleExecution.lease_expires_at <= current_time,
                    ),
                )
                .values(
                    state="running",
                    dispatch_state="sent",
                    attempt=ScheduleExecution.attempt + 1,
                    retry_at=None,
                    lease_owner=lease_owner,
                    lease_expires_at=current_time + policy.execution_lease_seconds,
                    started_at=current_time,
                )
            ),
        )
        if claimed.rowcount != 1:
            return None

        execution = session.get(ScheduleExecution, candidate_id)
        assert execution is not None

        schedule = session.get(Schedule, execution.schedule_id)
        if schedule is None:
            return None

        return ClaimedExecution(
            id=execution.id,
            schedule_id=schedule.id,
            task_name=schedule.task_name,
            task_contract_version=schedule.task_contract_version,
            payload=schedule.payload,
            scheduled_for=execution.scheduled_for,
            attempt=execution.attempt,
            lease_owner=lease_owner,
        )


def claim_execution_by_id(
    execution_id: str,
    generation: int,
    lease_owner: str,
    policy: SchedulingPolicy,
    *,
    now: float | None = None,
) -> ClaimedExecution | None:
    """Atomically lease the execution named by a cluster delivery message.

    Stale generations, retry delays, and live leases are rejected with ``None`` so
    the provider can decide whether the message should be retried or discarded.
    """
    current_time = time.time() if now is None else now
    with Session() as session, session.begin():
        claimed = cast(
            CursorResult,
            session.execute(
                update(ScheduleExecution)
                .where(
                    ScheduleExecution.id == execution_id,
                    ScheduleExecution.provider_generation == generation,
                    ScheduleExecution.state.in_(("pending", "running", "retry_wait")),
                    ScheduleExecution.schedule_id.in_(
                        select(Schedule.id).where(Schedule.status != "deleted")
                    ),
                    or_(
                        ScheduleExecution.retry_at.is_(None),
                        ScheduleExecution.retry_at <= current_time,
                    ),
                    or_(
                        ScheduleExecution.lease_expires_at.is_(None),
                        ScheduleExecution.lease_expires_at <= current_time,
                    ),
                )
                .values(
                    state="running",
                    dispatch_state="sent",
                    attempt=ScheduleExecution.attempt + 1,
                    retry_at=None,
                    lease_owner=lease_owner,
                    lease_expires_at=current_time + policy.execution_lease_seconds,
                    started_at=current_time,
                )
            ),
        )
        if claimed.rowcount != 1:
            return None

        execution = session.get(ScheduleExecution, execution_id)
        assert execution is not None

        schedule = session.get(Schedule, execution.schedule_id)
        if schedule is None:
            return None

        return ClaimedExecution(
            id=execution.id,
            schedule_id=schedule.id,
            task_name=schedule.task_name,
            task_contract_version=schedule.task_contract_version,
            payload=schedule.payload,
            scheduled_for=execution.scheduled_for,
            attempt=execution.attempt,
            lease_owner=lease_owner,
        )


def execution_delivery_state(
    execution_id: str, generation: int, *, now: float | None = None
) -> str:
    """Classify delivery as ``stale``, ``terminal``, ``busy``, or ``ready``."""
    current_time = time.time() if now is None else now
    with Session() as session:
        execution = session.get(ScheduleExecution, execution_id)
        if execution is None or execution.provider_generation != generation:
            return "stale"
        if execution.state in {"succeeded", "failed", "cancelled"}:
            return "terminal"
        if execution.retry_at is not None and execution.retry_at > current_time:
            return "busy"
        if (
            execution.lease_expires_at is not None
            and execution.lease_expires_at > current_time
        ):
            return "busy"
        return "ready"


def pending_dispatches(
    generation: int,
    batch_size: int,
    *,
    now: float | None = None,
) -> tuple[str, ...]:
    """Recover expired cluster leases and return executions awaiting delivery."""
    current_time = time.time() if now is None else now
    with Session() as session, session.begin():
        session.execute(
            update(ScheduleExecution)
            .where(
                ScheduleExecution.provider_generation == generation,
                ScheduleExecution.state == "running",
                ScheduleExecution.lease_expires_at <= current_time,
                ScheduleExecution.schedule_id.in_(
                    select(Schedule.id).where(Schedule.status != "deleted")
                ),
            )
            .values(
                state="pending",
                dispatch_state="pending",
                retry_at=None,
                lease_owner=None,
                lease_expires_at=None,
            )
        )
        return tuple(
            session.scalars(
                select(ScheduleExecution.id)
                .where(
                    ScheduleExecution.provider_generation == generation,
                    ScheduleExecution.state.in_(("pending", "retry_wait")),
                    ScheduleExecution.dispatch_state == "pending",
                    or_(
                        ScheduleExecution.retry_at.is_(None),
                        ScheduleExecution.retry_at <= current_time,
                    ),
                )
                .order_by(ScheduleExecution.created_at, ScheduleExecution.id)
                .limit(batch_size)
            )
        )


def mark_dispatched(execution_id: str, generation: int) -> bool:
    with Session() as session, session.begin():
        marked = cast(
            CursorResult,
            session.execute(
                update(ScheduleExecution)
                .where(
                    ScheduleExecution.id == execution_id,
                    ScheduleExecution.provider_generation == generation,
                    ScheduleExecution.dispatch_state == "pending",
                    ScheduleExecution.state.in_(("pending", "retry_wait")),
                )
                .values(dispatch_state="sent")
            ),
        )
        return marked.rowcount == 1


def purge_execution_history(
    policy: SchedulingPolicy,
    *,
    now: float | None = None,
) -> int:
    """Delete one bounded batch of terminal executions past the retention cutoff."""
    current_time = time.time() if now is None else now
    cutoff = current_time - policy.history_retention_days * 86_400
    with Session() as session, session.begin():
        execution_ids = tuple(
            session.scalars(
                select(ScheduleExecution.id)
                .where(
                    ScheduleExecution.state.in_(("succeeded", "failed", "cancelled")),
                    ScheduleExecution.completed_at < cutoff,
                )
                .order_by(ScheduleExecution.completed_at, ScheduleExecution.id)
                .limit(policy.claim_batch_size)
            )
        )
        if not execution_ids:
            return 0
        deleted = cast(
            CursorResult,
            session.execute(
                delete(ScheduleExecution).where(ScheduleExecution.id.in_(execution_ids))
            ),
        )
        return deleted.rowcount


def refresh_execution_lease(
    execution_id: str,
    lease_owner: str,
    policy: SchedulingPolicy,
    *,
    now: float | None = None,
) -> bool:
    current_time = time.time() if now is None else now
    with Session() as session, session.begin():
        refreshed = cast(
            CursorResult,
            session.execute(
                update(ScheduleExecution)
                .where(
                    ScheduleExecution.id == execution_id,
                    ScheduleExecution.state == "running",
                    ScheduleExecution.lease_owner == lease_owner,
                )
                .values(lease_expires_at=current_time + policy.execution_lease_seconds)
            ),
        )
        return refreshed.rowcount == 1


def _release_schedule_execution(session, schedule: Schedule, generation: int) -> None:
    """Release a schedule's slot and promote its latest coalesced occurrence."""
    schedule.active_execution_id = None
    if schedule.status == "deleted":
        return
    if schedule.pending_scheduled_for is not None:
        pending = schedule.pending_scheduled_for
        schedule.pending_scheduled_for = None
        _create_execution(session, schedule, pending, generation)
    elif schedule.next_run_at is None:
        schedule.status = "completed"


def complete_execution(
    claim: ClaimedExecution,
    generation: int,
    result: dict,
    *,
    now: float | None = None,
) -> bool:
    """Persist success if the caller still owns the execution lease.

    The schedule slot is released only for the execution currently attached to the
    schedule. ``False`` means ownership was lost and no state was changed.
    """
    current_time = time.time() if now is None else now
    with Session() as session, session.begin():
        execution = session.get(ScheduleExecution, claim.id)
        if (
            execution is None
            or execution.state != "running"
            or execution.lease_owner != claim.lease_owner
        ):
            return False
        execution.state = "succeeded"
        execution.completed_at = current_time
        execution.result = result
        execution.lease_owner = None
        execution.lease_expires_at = None
        schedule = session.get(Schedule, execution.schedule_id)
        if schedule is not None and schedule.active_execution_id == execution.id:
            _release_schedule_execution(session, schedule, generation)
        return True


def fail_execution(
    claim: ClaimedExecution,
    generation: int,
    max_attempts: int,
    initial_backoff_seconds: int,
    maximum_backoff_seconds: int,
    error: str,
    *,
    now: float | None = None,
) -> bool:
    """Persist a retry or terminal failure while the caller owns the lease.

    Retry delays use capped exponential backoff. A terminal failure releases the
    schedule slot so a coalesced recurring occurrence can proceed.
    """
    current_time = time.time() if now is None else now
    with Session() as session, session.begin():
        execution = session.get(ScheduleExecution, claim.id)
        if (
            execution is None
            or execution.state != "running"
            or execution.lease_owner != claim.lease_owner
        ):
            return False
        execution.error = error[:1024]
        execution.lease_owner = None
        execution.lease_expires_at = None
        schedule = session.get(Schedule, execution.schedule_id)
        if execution.attempt < max_attempts and (
            schedule is None or schedule.status != "deleted"
        ):
            delay = min(
                initial_backoff_seconds * 2 ** (execution.attempt - 1),
                maximum_backoff_seconds,
            )
            execution.state = "retry_wait"
            execution.dispatch_state = "pending"
            execution.retry_at = current_time + delay
            return True

        execution.state = "failed"
        execution.completed_at = current_time
        if schedule is not None and schedule.active_execution_id == execution.id:
            _release_schedule_execution(session, schedule, generation)
            if (
                schedule.status != "deleted"
                and schedule.next_run_at is None
                and schedule.active_execution_id is None
            ):
                schedule.status = "failed"
        return True


def run_claimed_execution(
    claim: ClaimedExecution,
    generation: int,
    registry: ScheduledTaskRegistry,
    policy: SchedulingPolicy,
) -> None:
    """Run a claimed task while renewing its lease and persist its outcome."""
    registration = registry.get(claim.task_name)
    if (
        registration is None
        or registration.contract_version != claim.task_contract_version
    ):
        fail_execution(
            claim,
            generation,
            1,
            1,
            1,
            "Scheduled task registration is unavailable",
        )
        return

    # Arbitrary task code can outlive the initial lease, so keep ownership alive in
    # a separate thread until success or failure has been persisted.
    heartbeat_stop = threading.Event()

    def refresh_lease() -> None:
        while not heartbeat_stop.wait(policy.lease_refresh_seconds):
            if not refresh_execution_lease(claim.id, claim.lease_owner, policy):
                return

    heartbeat = threading.Thread(
        target=refresh_lease,
        name=f"schedule-lease-{claim.id[:8]}",
        daemon=True,
    )
    heartbeat.start()
    try:
        payload = registry.validate_payload(
            claim.task_name, claim.task_contract_version, claim.payload
        )
        result = registration.execute(
            ScheduledTaskContext(
                schedule_id=claim.schedule_id,
                execution_id=claim.id,
                scheduled_for=claim.scheduled_for,
                attempt=claim.attempt,
            ),
            payload,
        )
        result_data = {} if result is None else result.data
        # Enforce the persistence contract at the task boundary and detach any
        # mutable result objects before storing or auditing them.
        result_data = orjson.loads(orjson.dumps(result_data))
        completed = complete_execution(claim, generation, result_data)
        if completed:
            try:
                log_audit(
                    "scheduled_task_execute",
                    0,
                    target=(
                        claim.schedule_id
                        if result is None or result.target is None
                        else result.target
                    ),
                    data={
                        "execution_id": claim.id,
                        "task_name": claim.task_name,
                        "scheduled_for": claim.scheduled_for,
                        "attempt": claim.attempt,
                        "result": result_data,
                    },
                )
            except Exception:  # noqa: BLE001 - audit cannot undo task effects.
                logger.exception(f"Failed to audit scheduled execution {claim.id}")
    except Exception as exc:  # noqa: BLE001 - task boundary records and retries failures.
        logger.exception(f"Scheduled task execution {claim.id} failed")
        failed = fail_execution(
            claim,
            generation,
            registration.max_attempts,
            registration.initial_backoff_seconds,
            registration.maximum_backoff_seconds,
            type(exc).__name__,
        )
        if failed:
            try:
                log_audit(
                    "scheduled_task_execute",
                    500,
                    target=claim.schedule_id,
                    data={
                        "execution_id": claim.id,
                        "task_name": claim.task_name,
                        "scheduled_for": claim.scheduled_for,
                        "attempt": claim.attempt,
                        "error": type(exc).__name__,
                    },
                )
            except Exception:  # noqa: BLE001 - preserve the task failure.
                logger.exception(f"Failed to audit scheduled execution {claim.id}")
    finally:
        heartbeat_stop.set()
        heartbeat.join(timeout=policy.lease_refresh_seconds + 1)
