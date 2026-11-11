from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from include.config.options import write_options
from include.database.models.identity import User
from include.database.models.operations import AuditEntry, OptionEntry, SystemStateEntry
from include.database.session import Base
from include.extensions.builtin import _extension as builtin
from include.transport.request_handler import EmptyRequestDataModel

pytestmark = pytest.mark.component


def test_server_info_reads_name_again_after_database_update(monkeypatch):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(
        engine,
        tables=[
            User.__table__,
            AuditEntry.__table__,
            OptionEntry.__table__,
            SystemStateEntry.__table__,
        ],
    )
    sessions = sessionmaker(bind=engine)
    monkeypatch.setattr(builtin, "Session", sessions)
    monkeypatch.setattr(
        builtin.lockdown_state_manager,
        "get_state",
        lambda: SimpleNamespace(enabled=False, reason=None),
    )
    monkeypatch.setattr(builtin, "collect_extension_flags", list)
    responses = []
    handler = SimpleNamespace(
        conclude_request=lambda code, data, message: responses.append((code, data))
    )
    with sessions.begin() as session:
        write_options(
            session,
            "server",
            {"name": "First Name"},
            expected_revisions={"name": 0},
        )

    builtin.RequestServerInfoHandler().handle(handler, EmptyRequestDataModel())
    with sessions.begin() as session:
        write_options(
            session,
            "server",
            {"name": "Second Name"},
            expected_revisions={"name": 1},
        )
    builtin.RequestServerInfoHandler().handle(handler, EmptyRequestDataModel())

    assert [response[1]["server_name"] for response in responses] == [
        "First Name",
        "Second Name",
    ]
    assert all(response[0] == 200 for response in responses)
