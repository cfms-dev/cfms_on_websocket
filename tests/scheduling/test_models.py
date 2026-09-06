from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session

import include.database.models  # noqa: F401
from include.database.models.identity import User
from include.database.models.scheduling import Schedule
from include.database.session import Base


def test_deleting_user_preserves_schedule_and_clears_attribution(tmp_path):
    database = create_engine(f"sqlite:///{tmp_path / 'scheduling.db'}")

    @event.listens_for(database, "connect")
    def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(database)
    with Session(database) as session, session.begin():
        session.add(
            User(
                username="schedule-owner",
                pass_hash="hash",
                passwd_last_modified=100.0,
                created_time=100.0,
                secret_key="secret",
            )
        )
        session.add(
            Schedule(
                id="user-schedule",
                task_name="test.record",
                task_contract_version=1,
                payload={"value": 1},
                trigger_type="date",
                trigger_data={"run_at": "2026-01-01T00:00:00+00:00"},
                timezone="UTC",
                next_run_at=200.0,
                created_by="schedule-owner",
                updated_by="schedule-owner",
            )
        )

    with Session(database) as session, session.begin():
        user = session.get(User, "schedule-owner")
        assert user is not None
        session.delete(user)

    with Session(database) as session:
        schedule = session.scalar(
            select(Schedule).where(Schedule.id == "user-schedule")
        )
        assert schedule is not None
        assert schedule.system_managed is False
        assert schedule.created_by is None
        assert schedule.updated_by is None
