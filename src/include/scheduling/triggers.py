import datetime as dt
from dataclasses import dataclass
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from apscheduler.triggers.base import BaseTrigger
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger
from apscheduler.triggers.interval import IntervalTrigger


class TriggerValidationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class TriggerAdvance:
    latest_due_at: float | None
    next_run_at: float | None


def _aware_datetime(value: object, field_name: str) -> dt.datetime:
    if not isinstance(value, str):
        raise TriggerValidationError(f"{field_name} must be an ISO 8601 string")
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError as exc:
        raise TriggerValidationError(
            f"{field_name} must be a valid ISO 8601 time"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise TriggerValidationError(f"{field_name} must include a UTC offset")
    return parsed


def build_trigger(
    trigger_type: str, trigger_data: dict[str, Any], timezone: str
) -> BaseTrigger:
    try:
        timezone_info = ZoneInfo(timezone)
    except ZoneInfoNotFoundError as exc:
        raise TriggerValidationError(f"Unknown IANA timezone {timezone!r}") from exc

    try:
        if trigger_type == "cron":
            expression = trigger_data.get("expression")
            if not isinstance(expression, str):
                raise TriggerValidationError("cron.expression must be a string")
            return CronTrigger.from_crontab(expression, timezone=timezone_info)
        if trigger_type == "date":
            run_at = _aware_datetime(trigger_data.get("run_at"), "date.run_at")
            return DateTrigger(run_date=run_at, timezone=timezone_info)
        if trigger_type == "interval":
            seconds = trigger_data.get("seconds")
            if (
                isinstance(seconds, bool)
                or not isinstance(seconds, int)
                or seconds <= 0
            ):
                raise TriggerValidationError(
                    "interval.seconds must be a positive integer"
                )
            start_at = _aware_datetime(
                trigger_data.get("start_at"), "interval.start_at"
            )
            return IntervalTrigger(
                seconds=seconds, start_date=start_at, timezone=timezone_info
            )
    except ValueError as exc:
        if isinstance(exc, TriggerValidationError):
            raise
        raise TriggerValidationError(str(exc)) from exc
    raise TriggerValidationError(f"Unsupported trigger type {trigger_type!r}")


def first_run_at(trigger: BaseTrigger, now: float) -> float | None:
    next_fire = trigger.get_next_fire_time(None, dt.datetime.fromtimestamp(now, dt.UTC))
    return None if next_fire is None else next_fire.timestamp()


def advance_trigger(
    trigger: BaseTrigger,
    current_run_at: float,
    now: float,
    misfire_grace_seconds: int,
) -> TriggerAdvance:
    """Coalesce eligible due fire times and return the first future fire time.

    Occurrences before the grace cutoff are skipped; multiple eligible occurrences
    collapse to the latest one so a delayed scheduler does not create a backlog.
    """
    cutoff = now - misfire_grace_seconds
    candidate = dt.datetime.fromtimestamp(current_run_at, dt.UTC)
    if current_run_at < cutoff:
        # Jump to the grace window instead of iterating through an unbounded outage.
        candidate = trigger.get_next_fire_time(
            None, dt.datetime.fromtimestamp(cutoff, dt.UTC)
        )
        if candidate is None:
            return TriggerAdvance(None, None)

    latest_due: dt.datetime | None = None
    iterations = 0
    now_datetime = dt.datetime.fromtimestamp(now, dt.UTC)
    while candidate is not None and candidate.timestamp() <= now:
        if candidate.timestamp() >= cutoff:
            latest_due = candidate
        candidate = trigger.get_next_fire_time(candidate, now_datetime)
        iterations += 1
        # Protect against malformed/custom triggers that fail to make useful
        # progress while still keeping legitimate dense schedules bounded.
        if iterations > 100_000:
            raise RuntimeError(
                "Trigger produced too many occurrences in one grace window"
            )

    return TriggerAdvance(
        None if latest_due is None else latest_due.timestamp(),
        None if candidate is None else candidate.timestamp(),
    )
