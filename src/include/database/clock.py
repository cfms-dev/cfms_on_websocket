from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession

_UNIX_EPOCH_JULIAN_DAY = 2_440_587.5
_SECONDS_PER_DAY = 86_400.0


def _database_time_expression(dialect_name: str):
    match dialect_name:
        case "sqlite":
            return (func.julianday("now") - _UNIX_EPOCH_JULIAN_DAY) * _SECONDS_PER_DAY
        case "postgresql":
            return func.extract("epoch", func.clock_timestamp())
        case "mysql":
            return func.unix_timestamp(func.current_timestamp(6))
        case _:
            raise ValueError(f"Unsupported database dialect: {dialect_name}")


def database_now(session: OrmSession) -> float:
    """Return the application database's current time as UTC Unix seconds."""
    value = session.scalar(
        select(_database_time_expression(session.get_bind().dialect.name))
    )
    assert value is not None
    return float(value)
