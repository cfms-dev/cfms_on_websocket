import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from sqlalchemy import event, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from include.config.constants import USERNAME_MAX_LENGTH
from include.database.models.identity import User, UserPermission
from include.database.session import Base
from include.domains.identity.handlers import users
from include.domains.identity.tokens import TokenPurpose

pytestmark = pytest.mark.component


@pytest.fixture
def name_sessions(monkeypatch, sqlite_engine_factory, tmp_path):
    engine = sqlite_engine_factory(tmp_path / "names.db")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)
    monkeypatch.setattr(users, "Session", sessions)
    return sessions


@pytest.mark.parametrize(
    ("handler_type", "field", "own_permission", "super_permission"),
    [
        (
            users.RequestSetUsernameHandler,
            "username",
            "set_username",
            "super_set_username",
        ),
        (
            users.RequestSetNicknameHandler,
            "nickname",
            "set_nickname",
            "super_set_nickname",
        ),
    ],
)
@pytest.mark.parametrize(
    ("grant", "self_target", "expected"),
    [
        (None, True, 403),
        (None, False, 403),
        ("own", True, 200),
        ("own", False, 403),
        ("super", True, 200),
        ("super", False, 200),
        ("other", True, 403),
        ("other", False, 403),
    ],
)
def test_name_permission_matrix(
    name_sessions,
    handler_type,
    field,
    own_permission,
    super_permission,
    grant,
    self_target,
    expected,
):
    with name_sessions.begin() as session:
        operator = User(username="operator", nickname="Original operator")
        target = User(username="target", nickname="Original target")
        if grant:
            permission = {
                "own": own_permission,
                "super": super_permission,
                "other": "super_set_nickname"
                if field == "username"
                else "super_set_username",
            }[grant]
            operator.rights.append(UserPermission(permission=permission, start_time=0))
        session.add_all([operator, target])
        session.flush()
        operator_id = operator.id
        target_id = operator.id if self_target else target.id
        original_username = "operator" if self_target else "target"
        original_nickname = "Original operator" if self_target else "Original target"

    responses = []
    handler = SimpleNamespace(
        user_id=operator_id,
        conclude_request=lambda **response: responses.append(response),
    )
    request = handler_type.request_model.model_validate(
        {"user_id": str(target_id).upper().replace("-", ""), field: "Updated"}
    )
    result = handler_type().handle(handler, request)

    assert responses[0]["code"] == result.code == expected
    assert responses[0]["data"] == {}
    assert result.target == str(target_id)
    assert result.user_id == operator_id
    with name_sessions() as session:
        target = session.get(User, target_id)
        assert target.username == (
            "Updated" if expected == 200 and field == "username" else original_username
        )
        assert target.nickname == (
            "Updated" if expected == 200 and field == "nickname" else original_nickname
        )
    if expected == 200:
        assert result.data["target_username"] == original_username
        if field == "username":
            assert result.data["new_username"] == "Updated"
    else:
        assert result.data is None


@pytest.fixture
def username_operator(name_sessions):
    with name_sessions.begin() as session:
        user = User(
            username="before",
            nickname="Nickname",
            rights=[UserPermission(permission="super_set_username", start_time=0)],
        )
        session.add(user)
        session.flush()
        return user.id


def test_same_username_preserves_identity_and_token(name_sessions, username_operator):
    with name_sessions() as session:
        user = session.get(User, username_operator)
        token = user.renew_token()
        signing_key = user.secret_key
    responses = []
    handler = SimpleNamespace(
        user_id=username_operator, conclude_request=lambda **r: responses.append(r)
    )
    request = users.RequestSetUsernameHandler.request_model.model_validate(
        {"user_id": str(username_operator), "username": "before"}
    )
    result = users.RequestSetUsernameHandler().handle(handler, request)
    assert responses[0]["code"] == result.code == 200
    with name_sessions() as session:
        user = session.get(User, username_operator)
        assert user.username == "before"
        assert user.nickname == "Nickname"
        assert user.secret_key == signing_key
        assert user.is_token_valid(token)


@pytest.mark.parametrize(
    ("permission", "expected"),
    [(None, 403), ("set_username", 403), ("super_set_username", 404)],
)
def test_username_authorization_precedes_missing_target_lookup(
    name_sessions, permission, expected
):
    with name_sessions.begin() as session:
        user = User(username="operator")
        if permission:
            user.rights.append(UserPermission(permission=permission, start_time=0))
        session.add(user)
        session.flush()
        operator_id = user.id
    missing_id = uuid.uuid4()
    responses = []
    handler = SimpleNamespace(
        user_id=operator_id, conclude_request=lambda **r: responses.append(r)
    )
    request = users.RequestSetUsernameHandler.request_model.model_validate(
        {"user_id": str(missing_id), "username": "Updated"}
    )
    result = users.RequestSetUsernameHandler().handle(handler, request)
    assert responses[0]["code"] == result.code == expected
    assert responses[0]["data"] == {}
    assert result.target == str(missing_id)
    assert result.data is None


@pytest.mark.parametrize("nickname_data", [{}, {"nickname": None}, {"nickname": ""}])
def test_nickname_clear_behavior(name_sessions, nickname_data):
    with name_sessions.begin() as session:
        user = User(
            username="operator",
            nickname="Original",
            rights=[UserPermission(permission="set_nickname", start_time=0)],
        )
        session.add(user)
        session.flush()
        user_id = user.id
    responses = []
    handler = SimpleNamespace(
        user_id=user_id, conclude_request=lambda **r: responses.append(r)
    )
    request = users.RequestSetNicknameHandler.request_model.model_validate(
        {"user_id": str(user_id), **nickname_data}
    )
    result = users.RequestSetNicknameHandler().handle(handler, request)
    assert responses[0]["code"] == result.code == 200
    with name_sessions() as session:
        user = session.get(User, user_id)
        assert user.nickname == nickname_data.get("nickname")
        assert user.username == "operator"


def test_duplicate_username_rolls_back(name_sessions, username_operator):
    with name_sessions.begin() as session:
        session.add(User(username="occupied"))
    responses = []
    handler = SimpleNamespace(
        user_id=username_operator, conclude_request=lambda **r: responses.append(r)
    )
    request = users.RequestSetUsernameHandler.request_model.model_validate(
        {"user_id": str(username_operator), "username": "occupied"}
    )
    result = users.RequestSetUsernameHandler().handle(handler, request)
    assert responses[0]["code"] == result.code == 400
    with name_sessions() as session:
        assert session.get(User, username_operator).username == "before"
        assert (
            len(session.scalars(select(User).where(User.username == "occupied")).all())
            == 1
        )


@pytest.mark.parametrize("backend", ["postgresql", "mysql"])
@pytest.mark.parametrize("constraint", ["ix_users_username", "unrelated_unique_index"])
def test_database_conflict_translation_is_specific_to_username(
    name_sessions,
    username_operator,
    backend,
    constraint,
):
    original = RuntimeError()
    if backend == "postgresql":
        original.pgcode = "23505"
        original.diag = SimpleNamespace(constraint_name=constraint)
    else:
        original.args = (1062, f"Duplicate entry for key '{constraint}'")
    failure = IntegrityError(
        "UPDATE users SET username=:username", {"username": "Updated"}, original
    )

    def fail_flush(_session, _context, _instances):
        raise failure

    responses = []
    handler = SimpleNamespace(
        user_id=username_operator, conclude_request=lambda **r: responses.append(r)
    )
    request = users.RequestSetUsernameHandler.request_model.model_validate(
        {"user_id": str(username_operator), "username": "Updated"}
    )
    event.listen(name_sessions.class_, "before_flush", fail_flush)
    try:
        if constraint == "ix_users_username":
            result = users.RequestSetUsernameHandler().handle(handler, request)
            assert responses[0]["code"] == result.code == 400
            assert responses[0]["data"] == {}
        else:
            with pytest.raises(IntegrityError) as error:
                users.RequestSetUsernameHandler().handle(handler, request)
            assert error.value is failure
            assert responses == []
    finally:
        event.remove(name_sessions.class_, "before_flush", fail_flush)
    with name_sessions() as session:
        assert session.get(User, username_operator).username == "before"


@pytest.mark.parametrize("occupied", [False, True])
def test_unrelated_integrity_error_is_not_translated(
    name_sessions, username_operator, occupied
):
    with name_sessions.begin() as session:
        if occupied:
            session.add(User(username="Updated"))
        session.connection().exec_driver_sql(
            "CREATE TRIGGER reject_rename BEFORE UPDATE OF username ON users "
            "BEGIN SELECT RAISE(ABORT, 'blocked update'); END"
        )
    responses = []
    handler = SimpleNamespace(
        user_id=username_operator, conclude_request=lambda **r: responses.append(r)
    )
    request = users.RequestSetUsernameHandler.request_model.model_validate(
        {"user_id": str(username_operator), "username": "Updated"}
    )
    with pytest.raises(IntegrityError):
        users.RequestSetUsernameHandler().handle(handler, request)
    assert responses == []
    with name_sessions() as session:
        assert session.get(User, username_operator).username == "before"


def test_competing_username_updates_leave_one_winner(name_sessions, username_operator):
    with name_sessions.begin() as session:
        target = User(username="second")
        session.add(target)
        session.flush()
        target_id = target.id
    barrier = threading.Barrier(2, timeout=10)
    engine = name_sessions.kw["bind"]

    def synchronize_updates(
        _connection, _cursor, statement, _parameters, _context, _many
    ):
        if statement.startswith("UPDATE users SET username="):
            barrier.wait()

    def rename(user_id):
        responses = []
        handler = SimpleNamespace(
            user_id=username_operator, conclude_request=lambda **r: responses.append(r)
        )
        request = users.RequestSetUsernameHandler.request_model.model_validate(
            {"user_id": str(user_id), "username": "claimed"}
        )
        result = users.RequestSetUsernameHandler().handle(handler, request)
        return user_id, responses[0], result

    event.listen(engine, "before_cursor_execute", synchronize_updates)
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(rename, user_id)
                for user_id in (username_operator, target_id)
            ]
            results = [future.result(timeout=20) for future in futures]
    finally:
        event.remove(engine, "before_cursor_execute", synchronize_updates)
    assert sorted(result.code for _, _, result in results) == [200, 400]
    with name_sessions() as session:
        for user_id, response, result in results:
            assert response["code"] == result.code
            original = "before" if user_id == username_operator else "second"
            assert session.get(User, user_id).username == (
                "claimed" if result.code == 200 else original
            )


@pytest.mark.parametrize(
    "value", ["", "u" * (USERNAME_MAX_LENGTH + 1), None, 12, True, [], {}]
)
def test_username_schema_rejects_invalid_names(value):
    with pytest.raises(ValidationError) as error:
        users.RequestSetUsernameHandler.request_model.model_validate(
            {"user_id": str(uuid.uuid4()), "username": value}
        )
    assert any(item["loc"] == ("username",) for item in error.value.errors())


@pytest.mark.parametrize(
    "payload",
    [
        {"username": "Valid"},
        {"user_id": "invalid", "username": "Valid"},
        {"user_id": str(uuid.uuid4())},
        {"user_id": str(uuid.uuid4()), "username": "Valid", "nickname": "Extra"},
    ],
)
def test_username_schema_requires_exact_fields(payload):
    with pytest.raises(ValidationError):
        users.RequestSetUsernameHandler.request_model.model_validate(payload)


def test_username_schema_and_token_requirements():
    user_id = uuid.uuid4()
    request = users.RequestSetUsernameHandler.request_model.model_validate(
        {
            "user_id": str(user_id).upper().replace("-", ""),
            "username": "u" * USERNAME_MAX_LENGTH,
        }
    )
    assert request.user_id == user_id
    assert request.username == "u" * USERNAME_MAX_LENGTH
    assert (
        users.RequestSetUsernameHandler.required_token_purpose
        == TokenPurpose.ESCALATION
    )
    assert (
        users.RequestSetNicknameHandler.required_token_purpose == TokenPurpose.GENERAL
    )
