import hashlib
import threading
import time
from dataclasses import dataclass

import orjson
from loguru import logger
from sqlalchemy import or_, select, update

from include.config.validation import SchedulingPolicy
from include.database.models.scheduling import (
    Schedule,
    ScheduleExecution,
    SchedulingRuntimeState,
)
from include.database.session import Session
from include.domains.operations.commands.audit import log_audit
from include.scheduling.contracts import ScheduledTaskContext
from include.scheduling.registry import ScheduledTaskRegistry
from include.scheduling.triggers import advance_trigger, build_trigger


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
    occurrence = int(round(scheduled_for * 1_000_000))
    return hashlib.sha256(f"{schedule_id}:{occurrence}".encode()).hexdigest()


def ensure_runtime_state(provider: str, now: float | None = None) -> int:
    current_time = time.time() if now is None else now
    with Session() as session, session.begin():
        state = session.get(SchedulingRuntimeState, 1)
        if state is None:
            state = SchedulingRuntimeState(
                id=1, provider=provider, generation=1, updated_at=current_time
            )
            session.add(state)
            return 1
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


def enqueue_due_schedules(
    generation: int,
    policy: SchedulingPolicy,
    *,
    now: float | None = None,
) -> int:
    current_time = time.time() if now is None else now
    with Session() as session:
        due_ids = session.scalars(
            select(Schedule.id)
            .where(
                Schedule.enabled.is_(True),
                Schedule.status == "active",
                Schedule.next_run_at.is_not(None),
                Schedule.next_run_at <= current_time,
            )
            .order_by(Schedule.next_run_at, Schedule.id)
            .limit(policy.claim_batch_size)
        ).all()

    created = 0
    for schedule_id in due_ids:
        with Session() as session, session.begin():
            schedule = session.get(Schedule, schedule_id)
            if (
                schedule is None
                or not schedule.enabled
                or schedule.status != "active"
                or schedule.next_run_at is None
                or schedule.next_run_at > current_time
            ):
                continue

            trigger = build_trigger(
                schedule.trigger_type, schedule.trigger_data, schedule.timezone
            )
            advance = advance_trigger(
                trigger,
                schedule.next_run_at,
                current_time,
                policy.misfire_grace_seconds,
            )
            schedule.next_run_at = advance.next_run_at
            if advance.latest_due_at is None:
                if advance.next_run_at is None and schedule.active_execution_id is None:
                    schedule.status = "completed"
                continue
            if schedule.active_execution_id is not None:
                schedule.pending_scheduled_for = advance.latest_due_at
                continue
            _create_execution(session, schedule, advance.latest_due_at, generation)
            created += 1
    return created


def claim_execution(
    generation: int,
    lease_owner: str,
    policy: SchedulingPolicy,
    *,
    now: float | None = None,
) -> ClaimedExecution | None:
    current_time = time.time() if now is None else now
    with Session() as session, session.begin():
        candidate_id = session.scalar(
            select(ScheduleExecution.id)
            .where(
                ScheduleExecution.provider_generation == generation,
                ScheduleExecution.state.in_(("pending", "running", "retry_wait")),
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

        claimed = session.execute(
            update(ScheduleExecution)
            .where(
                ScheduleExecution.id == candidate_id,
                ScheduleExecution.provider_generation == generation,
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
        )
        if claimed.rowcount != 1:
            return None

        execution = session.get(ScheduleExecution, candidate_id)
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


def refresh_execution_lease(
    execution_id: str,
    lease_owner: str,
    policy: SchedulingPolicy,
    *,
    now: float | None = None,
) -> bool:
    current_time = time.time() if now is None else now
    with Session() as session, session.begin():
        refreshed = session.execute(
            update(ScheduleExecution)
            .where(
                ScheduleExecution.id == execution_id,
                ScheduleExecution.state == "running",
                ScheduleExecution.lease_owner == lease_owner,
            )
            .values(lease_expires_at=current_time + policy.execution_lease_seconds)
        )
        return refreshed.rowcount == 1


def _release_schedule_execution(session, schedule: Schedule, generation: int) -> None:
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
        if execution.attempt < max_attempts:
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
        schedule = session.get(Schedule, execution.schedule_id)
        if schedule is not None and schedule.active_execution_id == execution.id:
            _release_schedule_execution(session, schedule, generation)
            if schedule.next_run_at is None and schedule.active_execution_id is None:
                schedule.status = "failed"
        return True


def run_claimed_execution(
    claim: ClaimedExecution,
    generation: int,
    registry: ScheduledTaskRegistry,
    policy: SchedulingPolicy,
) -> None:
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
