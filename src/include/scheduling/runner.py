import threading

import orjson
from loguru import logger

from include.config.validation import SchedulingPolicy
from include.domains.operations.commands.audit import log_audit
from include.scheduling.claims import refresh_execution_lease
from include.scheduling.contracts import ClaimedExecution, ScheduledTaskContext
from include.scheduling.outcomes import complete_execution, fail_execution
from include.scheduling.registry import ScheduledTaskRegistry


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

    if claim.attempt > registration.max_attempts:
        fail_execution(
            claim,
            generation,
            registration.max_attempts,
            registration.initial_backoff_seconds,
            registration.maximum_backoff_seconds,
            "Scheduled task maximum attempts exceeded",
        )
        return

    # Arbitrary task code can outlive the initial lease, so keep ownership alive in
    # a separate thread until success or failure has been persisted.
    heartbeat_stop = threading.Event()

    def refresh_lease() -> None:
        while not heartbeat_stop.wait(policy.lease_refresh_seconds):
            try:
                refreshed = refresh_execution_lease(claim.id, claim.lease_owner, policy)
            except Exception:  # noqa: BLE001 - task execution continues independently.
                logger.exception(
                    "Failed to refresh lease for scheduled execution {}", claim.id
                )
                return
            if not refreshed:
                logger.warning("Scheduled execution {} lost its lease", claim.id)
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
