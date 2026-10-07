from typing import ClassVar

import pytest
from pydantic import ValidationError

from include.config.constants import DOWNLOAD_TRANSFER_MIN_CHUNK_SIZE
from include.domains.documents.handlers.directories import (
    RequestCreateDirectoryHandler,
    RequestRestoreDirectoryHandler,
)
from include.domains.documents.handlers.documents import (
    RequestDownloadFileHandler,
    RequestGetDocumentHandler,
    RequestGetDocumentInfoHandler,
)
from include.domains.documents.handlers.search import RequestSearchHandler
from include.domains.identity.handlers.auth import RequestLoginHandler
from include.domains.identity.handlers.groups import (
    RequestChangeGroupPermissionsHandler,
    RequestCreateGroupHandler,
    RequestRenameGroupHandler,
)
from include.domains.identity.handlers.users import (
    RequestChangeUserPermissionsHandler,
    RequestCreateUserHandler,
    RequestManageUserStatusHandler,
    RequestSetPasswdHandler,
    RequestUpdateUserBlockHandler,
)
from include.domains.keyrings.handlers.keyrings import RequestListUserKeysHandler
from include.transport.request_handler import (
    REQUEST_UNSET,
    JsonInteger,
    NonEmptyString,
    Omittable,
    RequestDataModel,
    RequestHandler,
    validate_request_handler_models,
)


class IntegerRequest(RequestDataModel):
    value: JsonInteger


class TextRequest(RequestDataModel):
    value: NonEmptyString


class OptionalRequest(RequestDataModel):
    value: Omittable[str] = REQUEST_UNSET


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        pytest.param(0, 0, id="zero"),
        pytest.param(1, 1, id="integer"),
        pytest.param(1.0, 1, id="integral-float"),
        pytest.param(-2.0, -2, id="negative-integral-float"),
    ],
)
def test_json_integer_accepts_json_schema_integer_values(value, expected):
    request = IntegerRequest.model_validate({"value": value})

    assert request.value == expected


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(True, id="true"),
        pytest.param(False, id="false"),
        pytest.param("1", id="string"),
        pytest.param(1.5, id="fraction"),
        pytest.param(None, id="null"),
    ],
)
def test_json_integer_rejects_non_integer_values(value):
    with pytest.raises(ValidationError, match="value"):
        IntegerRequest.model_validate({"value": value})


def test_request_data_model_forbids_extra_fields():
    with pytest.raises(ValidationError, match="unexpected") as error:
        IntegerRequest.model_validate({"value": 1, "unexpected": True})

    assert error.value.errors()[0]["type"] == "extra_forbidden"


@pytest.mark.parametrize("value", ["   ", "  value  "], ids=["spaces", "padded"])
def test_request_non_empty_string_preserves_whitespace(value):
    request = TextRequest.model_validate({"value": value})

    assert request.value == value


def test_request_non_empty_string_rejects_empty_input():
    with pytest.raises(ValidationError, match="value"):
        TextRequest.model_validate({"value": ""})


def test_omittable_field_keeps_missing_value_unset():
    request = OptionalRequest.model_validate({})

    assert "value" not in request.model_fields_set
    assert request.model_dump(exclude_unset=True) == {}


def test_omittable_non_nullable_field_rejects_null():
    with pytest.raises(ValidationError, match="value"):
        OptionalRequest.model_validate({"value": None})


def test_login_request_accepts_protocol_two_factor_alias():
    request = RequestLoginHandler.request_model.model_validate(
        {"username": "alice", "password": "secret", "2fa_token": "123456"}
    )

    assert request.two_factor_token == "123456"


def test_login_request_rejects_internal_two_factor_field_name():
    with pytest.raises(ValidationError, match="two_factor_token"):
        RequestLoginHandler.request_model.model_validate(
            {"username": "alice", "password": "secret", "two_factor_token": "123456"}
        )


def test_group_rename_request_accepts_null_display_name():
    request = RequestRenameGroupHandler.request_model.model_validate(
        {"group_name": "staff", "display_name": None}
    )

    assert request.display_name is None
    assert "display_name" in request.model_fields_set


def test_group_rename_request_requires_display_name():
    with pytest.raises(ValidationError, match="display_name"):
        RequestRenameGroupHandler.request_model.model_validate({"group_name": "staff"})


@pytest.mark.parametrize("reason", ["incident", None], ids=["text", "null"])
def test_disabled_user_status_accepts_optional_reason(reason):
    request = RequestManageUserStatusHandler.request_model.model_validate(
        {"status": "disabled", "username": "alice", "reason": reason}
    )

    assert request.reason == reason


@pytest.mark.parametrize("reason", ["resolved", None], ids=["text", "null"])
def test_active_user_status_rejects_reason_field(reason):
    with pytest.raises(ValidationError, match="reason"):
        RequestManageUserStatusHandler.request_model.model_validate(
            {"status": "active", "username": "alice", "reason": reason}
        )


@pytest.mark.parametrize("reason", [None, "x" * 1024], ids=["null", "maximum-length"])
def test_update_user_block_accepts_nullable_or_maximum_reason(reason):
    request = RequestUpdateUserBlockHandler.request_model.model_validate(
        {"block_id": "block", "reason": reason}
    )

    assert request.reason == reason


def test_update_user_block_rejects_empty_reason():
    with pytest.raises(ValidationError, match="reason"):
        RequestUpdateUserBlockHandler.request_model.model_validate(
            {"block_id": "block", "reason": ""}
        )


@pytest.mark.parametrize(
    ("old_password_fields", "expected", "provided"),
    [
        pytest.param({}, None, False, id="omitted"),
        pytest.param({"old_passwd": None}, None, True, id="null"),
        pytest.param({"old_passwd": ""}, "", True, id="empty"),
        pytest.param({"old_passwd": "secret"}, "secret", True, id="credential"),
    ],
)
def test_password_request_preserves_old_password_mode(
    old_password_fields, expected, provided
):
    request = RequestSetPasswdHandler.request_model.model_validate(
        {"username": "alice", "new_passwd": "NewPassword123!", **old_password_fields}
    )

    assert request.old_passwd == expected
    assert ("old_passwd" in request.model_fields_set) is provided


_PERMISSION = {
    "permission": "read",
    "granted": False,
    "start_time": 10.0,
    "end_time": None,
}
_PERMISSION_REQUESTS = [
    pytest.param(
        RequestCreateUserHandler,
        {"username": "alice", "password": ""},
        id="create-user",
    ),
    pytest.param(
        RequestChangeUserPermissionsHandler,
        {"username": "alice"},
        id="change-user-permissions",
    ),
    pytest.param(RequestCreateGroupHandler, {"group_name": "staff"}, id="create-group"),
    pytest.param(
        RequestChangeGroupPermissionsHandler,
        {"group_name": "staff"},
        id="change-group-permissions",
    ),
]


@pytest.mark.parametrize(("handler_type", "base_data"), _PERMISSION_REQUESTS)
def test_permission_request_accepts_complete_structured_entry(handler_type, base_data):
    request = handler_type.request_model.model_validate(
        {**base_data, "permissions": [_PERMISSION]}
    )

    assert request.model_dump()["permissions"] == [_PERMISSION]


@pytest.mark.parametrize(("handler_type", "base_data"), _PERMISSION_REQUESTS)
@pytest.mark.parametrize(
    "permissions",
    [
        pytest.param(["read"], id="bare-name"),
        pytest.param(
            [{"permission": "read", "start_time": 10.0, "end_time": None}],
            id="missing-granted",
        ),
        pytest.param([{**_PERMISSION, "unexpected": True}], id="unknown-field"),
        pytest.param([{**_PERMISSION, "granted": "false"}], id="string-boolean"),
        pytest.param([{**_PERMISSION, "end_time": 9.0}], id="inverted-window"),
    ],
)
def test_permission_request_rejects_invalid_entry(handler_type, base_data, permissions):
    with pytest.raises(ValidationError, match="permissions"):
        handler_type.request_model.model_validate(
            {**base_data, "permissions": permissions}
        )


def test_list_user_keys_accepts_integral_float_pagination():
    request = RequestListUserKeysHandler.request_model.model_validate(
        {"offset": 1.0, "count": 10.0}
    )

    assert request.offset == 1
    assert request.count == 10


def test_list_user_keys_rejects_null_target_username():
    with pytest.raises(ValidationError, match="target_username"):
        RequestListUserKeysHandler.request_model.model_validate(
            {"target_username": None}
        )


@pytest.mark.parametrize(
    ("handler_type", "request_data"),
    [
        pytest.param(
            RequestCreateDirectoryHandler, {"name": "reports"}, id="directory"
        ),
        pytest.param(
            RequestGetDocumentInfoHandler,
            {"document_id": "document"},
            id="document-info",
        ),
    ],
)
def test_legacy_document_request_preserves_unknown_fields(handler_type, request_data):
    request = handler_type.request_model.model_validate(
        {**request_data, "legacy_option": True}
    )

    assert request.model_dump(exclude_unset=True) == {
        **request_data,
        "legacy_option": True,
    }


def test_get_document_request_rejects_unknown_fields():
    with pytest.raises(ValidationError, match="legacy_option"):
        RequestGetDocumentHandler.request_model.model_validate(
            {"document_id": "document", "legacy_option": True}
        )


def test_download_request_accepts_integral_float_transfer_values():
    request = RequestDownloadFileHandler.request_model.model_validate(
        {
            "task_id": "task",
            "offset": 1.0,
            "max_chunk_size": float(DOWNLOAD_TRANSFER_MIN_CHUNK_SIZE),
        }
    )

    assert request.offset == 1
    assert request.max_chunk_size == DOWNLOAD_TRANSFER_MIN_CHUNK_SIZE


def test_restore_directory_request_accepts_null_parent():
    request = RequestRestoreDirectoryHandler.request_model.model_validate(
        {"folder_id": "folder", "target_parent_id": None}
    )

    assert request.target_parent_id is None
    assert "target_parent_id" in request.model_fields_set


def test_restore_directory_request_rejects_empty_parent():
    with pytest.raises(ValidationError, match="target_parent_id"):
        RequestRestoreDirectoryHandler.request_model.model_validate(
            {"folder_id": "folder", "target_parent_id": ""}
        )


def test_search_request_accepts_query_at_node_name_capacity():
    request = RequestSearchHandler.request_model.model_validate({"query": "x" * 255})

    assert request.query == "x" * 255


def test_search_request_rejects_query_above_node_name_capacity():
    with pytest.raises(ValidationError, match="query"):
        RequestSearchHandler.request_model.model_validate({"query": "x" * 256})


class EmptyRequest(RequestDataModel):
    pass


class ValidHandler(RequestHandler):
    request_model = EmptyRequest

    def handle(self, _handler):
        return None


class LegacyHandler(RequestHandler):
    schema: ClassVar[dict[str, str]] = {"type": "object"}

    def handle(self, _handler):
        return None


def test_handler_contract_accepts_a_pydantic_request_model():
    assert validate_request_handler_models({"valid": ValidHandler}) is None


@pytest.mark.parametrize(
    ("action", "handler", "message"),
    [
        pytest.param(
            "legacy", LegacyHandler, "legacy.*request_model", id="legacy-schema"
        ),
        pytest.param(
            "plain", object, "plain.*inherit RequestHandler", id="plain-class"
        ),
    ],
)
def test_handler_contract_rejects_invalid_handler_models(action, handler, message):
    with pytest.raises(TypeError, match=message):
        validate_request_handler_models({action: handler})
