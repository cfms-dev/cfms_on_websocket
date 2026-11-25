import uuid

import pytest
from pydantic import ValidationError

from include.domains.identity.handlers.users import (
    RequestChangeUserGroupsHandler,
    RequestChangeUserPermissionsHandler,
    RequestDeleteUserHandler,
    RequestGetUserAvatarHandler,
    RequestGetUserInfoHandler,
    RequestManageUserStatusHandler,
    RequestSetNicknameHandler,
    RequestSetPasswdHandler,
    RequestSetUserAvatarHandler,
)
from include.domains.keyrings.handlers.keyrings import (
    RequestListUserKeysHandler,
    RequestUploadUserKeyHandler,
)
from include.domains.security.handlers.totp import (
    RequestDeleteTotpHandler,
    RequestGetTotpStatusHandler,
)

pytestmark = pytest.mark.unit
USER_ID = "aabbccdd-0000-4000-8000-000000000001"
USER_REQUESTS = [
    (RequestDeleteUserHandler, {}),
    (RequestSetNicknameHandler, {"nickname": "New nickname"}),
    (RequestGetUserAvatarHandler, {}),
    (RequestSetUserAvatarHandler, {"document_id": "document"}),
    (RequestChangeUserGroupsHandler, {"groups": []}),
    (RequestChangeUserPermissionsHandler, {"permissions": []}),
    (RequestManageUserStatusHandler, {"status": "disabled"}),
    (RequestSetPasswdHandler, {"new_passwd": "NewPassword123!"}),
]
OPTIONAL_USER_REQUESTS = [
    (RequestDeleteTotpHandler, {"password": "current-password"}, "username"),
    (RequestGetTotpStatusHandler, {}, "target"),
    (RequestUploadUserKeyHandler, {"content": "encrypted-key"}, "target_username"),
    (RequestListUserKeysHandler, {}, "target_username"),
]


@pytest.mark.parametrize(("handler_type", "data"), USER_REQUESTS)
def test_user_management_requires_an_explicit_uuid(handler_type, data):
    request = handler_type.request_model.model_validate({**data, "user_id": USER_ID})
    assert request.user_id == uuid.UUID(USER_ID)

    if handler_type is RequestSetPasswdHandler:
        request = handler_type.request_model.model_validate(data)
        assert request.model_fields_set == {"new_passwd"}
    else:
        with pytest.raises(ValidationError):
            handler_type.request_model.model_validate(data)
    with pytest.raises(ValidationError):
        handler_type.request_model.model_validate({**data, "username": "alice"})
    with pytest.raises(ValidationError):
        handler_type.request_model.model_validate(
            {**data, "user_id": USER_ID, "username": "alice"}
        )


@pytest.mark.parametrize(("handler_type", "data"), USER_REQUESTS)
@pytest.mark.parametrize("value", [None, "", "alice", True, 42, {}, []])
def test_user_management_rejects_invalid_uuid_values(handler_type, data, value):
    with pytest.raises(ValidationError):
        handler_type.request_model.model_validate({**data, "user_id": value})


@pytest.mark.parametrize(("handler_type", "data", "legacy"), OPTIONAL_USER_REQUESTS)
def test_optional_user_selectors_preserve_self_default(handler_type, data, legacy):
    omitted = handler_type.request_model.model_validate(data)
    assert "user_id" not in omitted.model_fields_set
    explicit = handler_type.request_model.model_validate({**data, "user_id": USER_ID})
    assert explicit.user_id == uuid.UUID(USER_ID)
    for value in (None, "alice", True, 42, {}, []):
        with pytest.raises(ValidationError):
            handler_type.request_model.model_validate({**data, "user_id": value})
    with pytest.raises(ValidationError):
        handler_type.request_model.model_validate({**data, legacy: "alice"})


@pytest.mark.parametrize("selector", [{"username": USER_ID}, {"user_id": USER_ID}])
def test_user_info_keeps_selector_meaning_explicit(selector):
    request = RequestGetUserInfoHandler.request_model.model_validate(selector)
    assert request.model_fields_set == selector.keys()
    if "username" in selector:
        assert request.username == USER_ID
    else:
        assert request.user_id == uuid.UUID(USER_ID)


@pytest.mark.parametrize(
    "selectors",
    [
        {},
        {"username": "alice", "user_id": USER_ID},
        {"username": None},
        {"user_id": None},
    ],
)
def test_user_info_rejects_missing_conflicting_or_null_selectors(selectors):
    with pytest.raises(ValidationError):
        RequestGetUserInfoHandler.request_model.model_validate(selectors)


@pytest.mark.parametrize(
    "selectors",
    [
        {"username": "alice"},
        {"username": "alice", "old_passwd": None},
        {"user_id": USER_ID, "old_passwd": "old"},
        {"username": "alice", "user_id": USER_ID},
        {"username": "alice", "user_id": USER_ID, "old_passwd": "old"},
    ],
)
def test_password_modes_cannot_mix_selectors(selectors):
    with pytest.raises(ValidationError):
        RequestSetPasswdHandler.request_model.model_validate(
            {**selectors, "new_passwd": "NewPassword123!"}
        )
