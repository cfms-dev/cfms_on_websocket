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
    from include.domains.identity.handlers.users import RequestManageUserStatusHandler

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
    with pytest.raises(ValidationError):
        RequestManageUserStatusHandler.request_model.model_validate(
            {"status": "active", "username": "alice", "reason": "resolved"}
        )


def test_nested_identity_and_keyring_models_preserve_omission_rules(
    monkeypatch, tmp_path
) -> None:
    from pydantic import ValidationError

    copyfile(PROJECT_ROOT / "src" / "config.toml.sample", tmp_path / "config.toml")
    monkeypatch.chdir(tmp_path)

    from include.domains.identity.handlers.users import RequestCreateUserHandler
    from include.domains.keyrings.handlers.keyrings import RequestListUserKeysHandler

    RequestCreateUserHandler.request_model.model_validate(
        {
            "username": "alice",
            "password": "",
            "permissions": [{"permission": "read", "start_time": 0}],
        }
    )
    with pytest.raises(ValidationError):
        RequestCreateUserHandler.request_model.model_validate(
            {
                "username": "alice",
                "password": "",
                "permissions": [
                    {"permission": "read", "start_time": 0, "end_time": None}
                ],
            }
        )

    RequestListUserKeysHandler.request_model.model_validate(
        {"offset": 1.0, "count": 10.0}
    )
    with pytest.raises(ValidationError):
        RequestListUserKeysHandler.request_model.model_validate(
            {"target_username": None}
        )
