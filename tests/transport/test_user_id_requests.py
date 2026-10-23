import uuid

import pytest
from pydantic import ValidationError

from include.domains.access.handlers import (
    RequestGrantAccessHandler,
    RequestViewAccessEntriesHandler,
)
from include.domains.identity.handlers.users import (
    RequestBlockUserHandler,
    RequestChangeUserGroupsHandler,
    RequestChangeUserPermissionsHandler,
    RequestDeleteUserHandler,
    RequestGetUserAvatarHandler,
    RequestGetUserInfoHandler,
    RequestListUserBlocksHandler,
    RequestManageUserStatusHandler,
    RequestRenameUserHandler,
    RequestSetPasswdHandler,
    RequestSetUserAvatarHandler,
)
from include.domains.keyrings.handlers.keyrings import (
    RequestListUserKeysHandler,
    RequestUploadUserKeyHandler,
)
from include.domains.security.handlers.two_factor import (
    RequestDisable2FAHandler,
    RequestGet2FAStatusHandler,
)

pytestmark = pytest.mark.unit
USER_ID = "aabbccdd-0000-4000-8000-000000000001"
USER_REQUESTS = [
    (RequestDeleteUserHandler, {}),
    (RequestRenameUserHandler, {"nickname": "New nickname"}),
    (RequestBlockUserHandler, {"target": {"type": "all"}, "block_types": ["read"]}),
    (RequestListUserBlocksHandler, {}),
    (RequestGetUserAvatarHandler, {}),
    (RequestSetUserAvatarHandler, {"document_id": "document"}),
    (RequestChangeUserGroupsHandler, {"groups": []}),
    (RequestChangeUserPermissionsHandler, {"permissions": []}),
    (RequestManageUserStatusHandler, {"status": "disabled"}),
    (RequestSetPasswdHandler, {"new_passwd": "NewPassword123!"}),
]
OPTIONAL_USER_REQUESTS = [
    (RequestDisable2FAHandler, {"password": "current-password"}, "username"),
    (RequestGet2FAStatusHandler, {}, "target"),
    (RequestUploadUserKeyHandler, {"content": "encrypted-key"}, "target_username"),
    (RequestListUserKeysHandler, {}, "target_username"),
]


@pytest.mark.parametrize(("handler_type", "data"), USER_REQUESTS)
def test_user_management_requires_an_explicit_uuid(handler_type, data):
    request = handler_type.request_model.model_validate({**data, "user_id": USER_ID})
    assert request.user_id == uuid.UUID(USER_ID)

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


@pytest.mark.parametrize(
    ("handler_type", "base_data", "type_field", "identifier_field"),
    [
        (
            RequestGrantAccessHandler,
            {
                "target_type": "document",
                "target_identifier": "document",
                "access_types": ["read"],
                "start_time": 0,
            },
            "entity_type",
            "entity_identifier",
        ),
        (RequestViewAccessEntriesHandler, {}, "object_type", "object_identifier"),
    ],
)
def test_access_identifiers_validate_user_ids_without_restricting_group_names(
    handler_type, base_data, type_field, identifier_field
):
    for entity_type, identifier in (("user", USER_ID), ("group", "staff")):
        request = handler_type.request_model.model_validate(
            {**base_data, type_field: entity_type, identifier_field: identifier}
        )
        assert getattr(request, identifier_field) == identifier
    with pytest.raises(ValidationError):
        handler_type.request_model.model_validate(
            {**base_data, type_field: "user", identifier_field: "alice"}
        )
