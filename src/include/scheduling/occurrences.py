import hashlib

from include.database.models.scheduling import Schedule, ScheduleExecution


def execution_id(schedule_id: str, scheduled_for: float) -> str:
    """Return the deterministic SHA-256 ID for one scheduled occurrence."""
    occurrence = round(scheduled_for * 1_000_000)
    return hashlib.sha256(f"{schedule_id}:{occurrence}".encode()).hexdigest()


def create_execution(
    session,
    schedule: Schedule,
    scheduled_for: float,
    generation: int,
    current_time: float,
) -> ScheduleExecution:
    """Create an execution snapshot and reserve its schedule's active slot."""
    item = ScheduleExecution(
        id=execution_id(schedule.id, scheduled_for),
        schedule_id=schedule.id,
        task_name=schedule.task_name,
        task_contract_version=schedule.task_contract_version,
        payload=schedule.payload,
        provider_generation=generation,
        scheduled_for=scheduled_for,
        created_at=current_time,
    )
    session.add(item)
    schedule.active_execution_id = item.id
    return item
