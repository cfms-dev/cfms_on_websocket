import pytest
from sqlalchemy.orm import Session

from include.database.models import User
from include.database.session import Base
from tests.support.database import sqlite_engine_factory

__all__ = ["sqlite_engine_factory"]


@pytest.fixture
def schedule_database(sqlite_engine_factory, tmp_path):
    database = sqlite_engine_factory(tmp_path / "scheduling.db", timeout_seconds=10)
    Base.metadata.create_all(database)
    with Session(database) as session, session.begin():
        session.add(
            User(
                username="admin",
                pass_hash="hash",
                passwd_last_modified=100.0,
                created_time=100.0,
                secret_key="secret",
            )
        )
    return database
