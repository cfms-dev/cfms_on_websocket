from types import SimpleNamespace

import pytest
from sqlalchemy import select
from sqlalchemy.exc import TimeoutError as SQLAlchemyTimeoutError
from sqlalchemy.orm import sessionmaker

import include.database.models  # noqa: F401
from include.config.options import CORE_POLICY_TYPES, read_options, write_options
from include.config.validation import ConfigValidationError, PasswordPolicy
from include.database.models.auth import UserPasswordCredential
from include.database.models.documents import Folder
from include.database.models.identity import User
from include.database.models.operations import AuditEntry
from include.database.models.scheduling import Schedule
from include.database.session import Base
from include.domains.access.authorization.access_rules import set_access_rules
from include.domains.access.authorization.evaluation import check_access_requirements
from include.domains.identity.auth.password_state import (
    assess_password,
    password_change_requirement,
)
from include.domains.identity.auth.types import InvalidAuthenticationAttempt
from include.extensions.builtin import permission_cleanup
from include.scheduling import ScheduledTaskRegistry, reconciliation
from include.transport import request_entrypoint
from tests.support.database import sqlite_engine_factory

__all__ = ["sqlite_engine_factory"]

pytestmark = pytest.mark.component


@pytest.fixture
def policy_sessions(sqlite_engine_factory):
    engine = sqlite_engine_factory()
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


@pytest.mark.parametrize(
    ("namespace", "key", "value"),
    [
        ("security.password", "passwd_min_length", 12),
        ("security.auth_throttle", "enabled", False),
        ("security.request_rate_control", "action_costs", {"core.search.query": 4}),
        ("maintenance.audit_retention", "retention_days", 7),
        ("identity.permission_retention", "cleanup_interval_seconds", 180),
        ("document.upload", "start_timeout_seconds", 800),
        ("document.upload.creation_risk_control", "mode", "observe"),
        ("document.download.risk_control", "mode", "enforce"),
        ("scheduling", "misfire_grace_seconds", 30),
    ],
)
def test_database_changes_apply_to_next_policy_snapshot(
    policy_sessions, namespace, key, value
):
    policy_type = CORE_POLICY_TYPES[namespace]
    with policy_sessions() as session:
        original = policy_type.from_options(session)
    with policy_sessions.begin() as session:
        write_options(session, namespace, {key: value}, expected_revisions={key: 0})
    with policy_sessions() as session:
        updated = policy_type.from_options(session)
        assert read_options(session, namespace)[key].value == value
    assert getattr(updated, key) == (
        tuple(value.items()) if key == "action_costs" else value
    )
    assert getattr(original, key) != getattr(updated, key)


def test_password_assessment_is_invalidated_by_database_policy_change(policy_sessions):
    with policy_sessions.begin() as session:
        user = User(username="policy-user")
        credential = UserPasswordCredential(
            user=user, pass_hash="unused", passwd_last_modified=1000
        )
        session.add(credential)
        session.flush()
        policy = PasswordPolicy.from_options(session)
        assessment = assess_password(credential, "Abcdef12!", policy)
        assert assessment.rules_satisfied
        context = SimpleNamespace(
            evidence=[
                SimpleNamespace(
                    method="password", credential_id=credential.credential_id
                )
            ]
        )
        write_options(
            session,
            "security.password",
            {"passwd_min_length": 12},
            expected_revisions={"passwd_min_length": 0},
        )
        with pytest.raises(InvalidAuthenticationAttempt):
            password_change_requirement(session, user, context, assessment)
        assert not assess_password(
            credential, "Abcdef12!", PasswordPolicy.from_options(session)
        ).rules_satisfied


def test_access_recursion_uses_the_latest_database_value(policy_sessions):
    with policy_sessions.begin() as session:
        user = User(username="reader")
        parent = Folder(id="/", name="/", inherit=False)
        child = Folder(id="child", name="child", parent_id="/", inherit=True)
        session.add_all([user, parent])
        session.flush()
        session.add(child)
        session.flush()
        set_access_rules(
            parent,
            {"read": [{"match": "any", "match_groups": []}]},
            inherit_parent=False,
        )
        set_access_rules(child, {"read": []})
        assert not check_access_requirements(session, user, child)
        write_options(
            session,
            "access",
            {"enable_access_recursive_check": False},
            expected_revisions={"enable_access_recursive_check": 0},
        )
        assert check_access_requirements(session, user, child)


def test_cleanup_interval_changes_are_reconciled_without_restart(
    policy_sessions, monkeypatch
):
    monkeypatch.setattr(permission_cleanup, "Session", policy_sessions)
    monkeypatch.setattr(reconciliation, "Session", policy_sessions)
    registry = ScheduledTaskRegistry((permission_cleanup.permission_cleanup_task,))
    assert reconciliation.synchronize_system_schedules(registry, now=1000) == 1
    with policy_sessions.begin() as session:
        schedule = session.get(Schedule, "builtin.permission_cleanup")
        assert schedule.trigger_data["seconds"] == 3600
        revision = schedule.revision
        write_options(
            session,
            "identity.permission_retention",
            {"cleanup_interval_seconds": 180},
            expected_revisions={"cleanup_interval_seconds": 0},
        )
    assert reconciliation.synchronize_system_schedules(registry, now=1001) == 1
    with policy_sessions() as session:
        schedule = session.get(Schedule, "builtin.permission_cleanup")
        assert schedule.trigger_data["seconds"] == 180
        assert schedule.revision == revision + 1


def test_connection_policy_pool_timeout_returns_service_unavailable(monkeypatch):
    def exhausted(_ip):
        raise SQLAlchemyTimeoutError()

    monkeypatch.setattr(
        request_entrypoint, "get_client_ip", lambda _connection: "192.0.2.1"
    )
    monkeypatch.setattr(
        request_entrypoint.LoginGuard,
        "evaluate_subnet_access",
        lambda _ip: SimpleNamespace(allowed=True),
    )
    monkeypatch.setattr(request_entrypoint, "check_connection_attempt", exhausted)
    response = request_entrypoint.global_process_request(None, None)
    assert response.status_code == 503
    assert int(response.headers["Retry-After"]) > 0


def test_invalid_password_rules_roll_back_policy_and_audit(policy_sessions):
    with pytest.raises(ConfigValidationError), policy_sessions.begin() as session:
        write_options(
            session,
            "security.password",
            {"passwd_rules": ["["]},
            expected_revisions={"passwd_rules": 0},
        )
    with policy_sessions() as session:
        assert read_options(session, "security.password")["passwd_rules"].revision == 0
        assert session.scalar(select(AuditEntry)) is None
