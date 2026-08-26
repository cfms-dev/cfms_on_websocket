from pathlib import Path
from shutil import copyfile

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _integer_request(monkeypatch, tmp_path):
    copyfile(PROJECT_ROOT / "src" / "config.toml.sample", tmp_path / "config.toml")
    monkeypatch.chdir(tmp_path)

    from include.transport.request_handler import JsonInteger, RequestDataModel

    class IntegerRequest(RequestDataModel):
        value: JsonInteger

    return IntegerRequest


@pytest.mark.parametrize("value", [0, 1, 1.0, -2.0])
def test_json_integer_accepts_json_schema_integer_values(
    monkeypatch, tmp_path, value
) -> None:
    request_model = _integer_request(monkeypatch, tmp_path)

    assert request_model.model_validate({"value": value}).value == int(value)


@pytest.mark.parametrize("value", [True, False, "1", 1.5, None])
def test_json_integer_rejects_non_integer_values(monkeypatch, tmp_path, value) -> None:
    from pydantic import ValidationError

    request_model = _integer_request(monkeypatch, tmp_path)

    with pytest.raises(ValidationError):
        request_model.model_validate({"value": value})


def test_request_data_model_is_strict_and_forbids_extra_fields(
    monkeypatch, tmp_path
) -> None:
    from pydantic import ValidationError

    request_model = _integer_request(monkeypatch, tmp_path)

    with pytest.raises(ValidationError) as type_error:
        request_model.model_validate({"value": "1"})
    with pytest.raises(ValidationError) as extra_error:
        request_model.model_validate({"value": 1, "unexpected": True})

    assert type_error.value.errors()[0]["type"] == "int_type"
    assert extra_error.value.errors()[0]["type"] == "extra_forbidden"


def test_request_non_empty_string_preserves_whitespace(monkeypatch, tmp_path) -> None:
    from pydantic import ValidationError

    copyfile(PROJECT_ROOT / "src" / "config.toml.sample", tmp_path / "config.toml")
    monkeypatch.chdir(tmp_path)

    from include.transport.request_handler import (
        NonEmptyString,
        RequestDataModel,
    )

    class TextRequest(RequestDataModel):
        value: NonEmptyString

    assert TextRequest.model_validate({"value": "   "}).value == "   "
    assert TextRequest.model_validate({"value": "  value  "}).value == "  value  "
    with pytest.raises(ValidationError):
        TextRequest.model_validate({"value": ""})


def test_omittable_field_distinguishes_missing_from_null(monkeypatch, tmp_path) -> None:
    from pydantic import ValidationError

    copyfile(PROJECT_ROOT / "src" / "config.toml.sample", tmp_path / "config.toml")
    monkeypatch.chdir(tmp_path)

    from include.transport.request_handler import (
        REQUEST_UNSET,
        Omittable,
        RequestDataModel,
    )

    class OptionalRequest(RequestDataModel):
        value: Omittable[str] = REQUEST_UNSET

    request = OptionalRequest.model_validate({})
    assert "value" not in request.model_fields_set

    with pytest.raises(ValidationError):
        OptionalRequest.model_validate({"value": None})


def test_identity_request_models_preserve_conditional_and_alias_rules(
    monkeypatch, tmp_path
) -> None:
    from pydantic import ValidationError

    copyfile(PROJECT_ROOT / "src" / "config.toml.sample", tmp_path / "config.toml")
    monkeypatch.chdir(tmp_path)

    from include.domains.identity.handlers.auth import RequestLoginHandler
    from include.domains.identity.handlers.groups import RequestRenameGroupHandler
    from include.domains.identity.handlers.users import (
        RequestManageUserStatusHandler,
        RequestUpdateUserBlockHandler,
    )

    RequestLoginHandler.request_model.model_validate(
        {"username": "alice", "password": "secret", "2fa_token": "123456"}
    )
    with pytest.raises(ValidationError):
        RequestLoginHandler.request_model.model_validate(
            {
                "username": "alice",
                "password": "secret",
                "two_factor_token": "123456",
            }
        )

    RequestRenameGroupHandler.request_model.model_validate(
        {"group_name": "staff", "display_name": None}
    )
    with pytest.raises(ValidationError):
        RequestRenameGroupHandler.request_model.model_validate({"group_name": "staff"})

    RequestManageUserStatusHandler.request_model.model_validate(
        {"status": "disabled", "username": "alice", "reason": "incident"}
    )
    RequestManageUserStatusHandler.request_model.model_validate(
        {"status": "disabled", "username": "alice", "reason": None}
    )
    RequestUpdateUserBlockHandler.request_model.model_validate(
        {"block_id": "block", "reason": None}
    )
    RequestUpdateUserBlockHandler.request_model.model_validate(
        {"block_id": "block", "reason": "x" * 1024}
    )
    with pytest.raises(ValidationError):
        RequestManageUserStatusHandler.request_model.model_validate(
            {"status": "active", "username": "alice", "reason": "resolved"}
        )
    with pytest.raises(ValidationError):
        RequestManageUserStatusHandler.request_model.model_validate(
            {"status": "active", "username": "alice", "reason": None}
        )
    with pytest.raises(ValidationError):
        RequestUpdateUserBlockHandler.request_model.model_validate(
            {"block_id": "block", "reason": ""}
        )


def test_set_password_request_preserves_compatible_mode_values(
    monkeypatch, tmp_path
) -> None:
    copyfile(PROJECT_ROOT / "src" / "config.toml.sample", tmp_path / "config.toml")
    monkeypatch.chdir(tmp_path)

    from include.domains.identity.handlers.users import RequestSetPasswdHandler

    request_data = {"username": "alice", "new_passwd": "NewPassword123!"}

    omitted = RequestSetPasswdHandler.request_model.model_validate(request_data)
    null = RequestSetPasswdHandler.request_model.model_validate(
        {**request_data, "old_passwd": None}
    )
    empty = RequestSetPasswdHandler.request_model.model_validate(
        {**request_data, "old_passwd": ""}
    )
    provided = RequestSetPasswdHandler.request_model.model_validate(
        {**request_data, "old_passwd": "secret"}
    )

    assert omitted.old_passwd is None
    assert "old_passwd" not in omitted.model_fields_set
    assert null.old_passwd is None
    assert "old_passwd" in null.model_fields_set
    assert empty.old_passwd == ""
    assert "old_passwd" in empty.model_fields_set
    assert provided.old_passwd == "secret"
    assert "old_passwd" in provided.model_fields_set


def test_identity_permission_requests_require_complete_structured_entries(
    monkeypatch, tmp_path
) -> None:
    from pydantic import ValidationError

    copyfile(PROJECT_ROOT / "src" / "config.toml.sample", tmp_path / "config.toml")
    monkeypatch.chdir(tmp_path)

    from include.domains.identity.handlers.groups import (
        RequestChangeGroupPermissionsHandler,
        RequestCreateGroupHandler,
    )
    from include.domains.identity.handlers.users import (
        RequestChangeUserPermissionsHandler,
        RequestCreateUserHandler,
    )
    from include.domains.keyrings.handlers.keyrings import RequestListUserKeysHandler

    permission = {
        "permission": "read",
        "granted": False,
        "start_time": 10.0,
        "end_time": None,
    }
    request_cases = (
        (
            RequestCreateUserHandler.request_model,
            {"username": "alice", "password": ""},
        ),
        (
            RequestChangeUserPermissionsHandler.request_model,
            {"username": "alice"},
        ),
        (RequestCreateGroupHandler.request_model, {"group_name": "staff"}),
        (
            RequestChangeGroupPermissionsHandler.request_model,
            {"group_name": "staff"},
        ),
    )

    for request_model, base_data in request_cases:
        request_model.model_validate({**base_data, "permissions": [permission]})

        invalid_permissions = (
            ["read"],
            [{key: value for key, value in permission.items() if key != "granted"}],
            [{**permission, "unexpected": True}],
            [{**permission, "granted": "false"}],
            [{**permission, "end_time": 9.0}],
        )
        for invalid in invalid_permissions:
            with pytest.raises(ValidationError):
                request_model.model_validate({**base_data, "permissions": invalid})

    RequestListUserKeysHandler.request_model.model_validate(
        {"offset": 1.0, "count": 10.0}
    )
    with pytest.raises(ValidationError):
        RequestListUserKeysHandler.request_model.model_validate(
            {"target_username": None}
        )


def test_document_request_models_preserve_legacy_extra_field_rules(
    monkeypatch, tmp_path
) -> None:
    from pydantic import ValidationError

    copyfile(PROJECT_ROOT / "src" / "config.toml.sample", tmp_path / "config.toml")
    monkeypatch.chdir(tmp_path)

    from include.domains.documents.handlers.directories import (
        RequestCreateDirectoryHandler,
    )
    from include.domains.documents.handlers.documents import (
        RequestGetDocumentHandler,
        RequestGetDocumentInfoHandler,
    )

    RequestCreateDirectoryHandler.request_model.model_validate(
        {"name": "reports", "legacy_option": True}
    )
    RequestGetDocumentInfoHandler.request_model.model_validate(
        {"document_id": "document", "legacy_option": True}
    )
    with pytest.raises(ValidationError):
        RequestGetDocumentHandler.request_model.model_validate(
            {"document_id": "document", "legacy_option": True}
        )


def test_document_request_models_preserve_transfer_and_restore_constraints(
    monkeypatch, tmp_path
) -> None:
    from pydantic import ValidationError

    copyfile(PROJECT_ROOT / "src" / "config.toml.sample", tmp_path / "config.toml")
    monkeypatch.chdir(tmp_path)

    from include.config.constants import DOWNLOAD_TRANSFER_MIN_CHUNK_SIZE
    from include.domains.documents.handlers.directories import (
        RequestRestoreDirectoryHandler,
    )
    from include.domains.documents.handlers.documents import RequestDownloadFileHandler

    RequestDownloadFileHandler.request_model.model_validate(
        {
            "task_id": "task",
            "offset": 1.0,
            "max_chunk_size": float(DOWNLOAD_TRANSFER_MIN_CHUNK_SIZE),
        }
    )
    RequestRestoreDirectoryHandler.request_model.model_validate(
        {"folder_id": "folder", "target_parent_id": None}
    )
    with pytest.raises(ValidationError):
        RequestRestoreDirectoryHandler.request_model.model_validate(
            {"folder_id": "folder", "target_parent_id": ""}
        )


def test_search_query_length_matches_node_name_capacity(monkeypatch, tmp_path) -> None:
    from pydantic import ValidationError

    copyfile(PROJECT_ROOT / "src" / "config.toml.sample", tmp_path / "config.toml")
    monkeypatch.chdir(tmp_path)

    from include.domains.documents.handlers.search import RequestSearchHandler

    request_model = RequestSearchHandler.request_model
    assert request_model.model_validate({"query": "x" * 255}).query == "x" * 255
    with pytest.raises(ValidationError):
        request_model.model_validate({"query": "x" * 256})


def test_handler_contract_requires_a_pydantic_request_model(
    monkeypatch, tmp_path
) -> None:
    copyfile(PROJECT_ROOT / "src" / "config.toml.sample", tmp_path / "config.toml")
    monkeypatch.chdir(tmp_path)

    from include.transport.request_handler import (
        RequestDataModel,
        RequestHandler,
        validate_request_handler_models,
    )

    class EmptyRequest(RequestDataModel):
        pass

    class ValidHandler(RequestHandler):
        request_model = EmptyRequest

        def handle(self, _handler):
            return None

    class LegacyHandler(RequestHandler):
        schema = {"type": "object"}

        def handle(self, _handler):
            return None

    validate_request_handler_models({"valid": ValidHandler})

    with pytest.raises(TypeError, match="legacy.*request_model"):
        validate_request_handler_models({"legacy": LegacyHandler})
    with pytest.raises(TypeError, match="plain.*inherit RequestHandler"):
        validate_request_handler_models({"plain": object})
