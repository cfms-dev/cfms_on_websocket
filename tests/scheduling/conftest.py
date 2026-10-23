import uuid

import pytest
from sqlalchemy.orm import Session

from include.database.models import User
from include.database.session import Base
from tests.support.database import sqlite_engine_factory

ADMIN_ID = uuid.UUID("aedaee2f-36aa-45a2-8dde-b1df1c662d05")

__all__ = ["sqlite_engine_factory"]


@pytest.fixture
def schedule_database(sqlite_engine_factory, tmp_path):
    database = sqlite_engine_factory(tmp_path / "scheduling.db", timeout_seconds=10)
    Base.metadata.create_all(database)
    with Session(database) as session, session.begin():
        session.add(
            User(
                username="admin",
                id=ADMIN_ID,
                created_time=100.0,
                secret_key="secret",
            )
        )
    return database
