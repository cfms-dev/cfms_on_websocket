"""Discover and manage explicitly exposed database-backed settings."""

from typing import Annotated, Any

from pydantic import Field, field_validator

from include.config.options import (
    OptionConflictError,
    OptionValidationError,
    ResolvedOption,
    describe_settings,
    get_setting_definitions,
    read_options,
    write_options,
)
from include.database.models.identity import User
from include.database.options import OptionKey, OptionNamespace, OptionValue
from include.database.session import Session
from include.domains.access.permissions import Permissions
from include.transport.request_handler import (
    REQUEST_UNSET,
    Omittable,
    RequestDataModel,
    RequestHandler,
    Result,
)
from include.types import JsonInteger


class _ListSettingsRequest(RequestDataModel):
    namespace: Omittable[OptionNamespace] = REQUEST_UNSET


class _GetSettingsRequest(RequestDataModel):
    namespace: OptionNamespace
    keys: Omittable[Annotated[list[OptionKey], Field(min_length=1)]] = REQUEST_UNSET

    @field_validator("keys")
    @classmethod
    def reject_duplicate_keys(cls, keys):
        if keys is not REQUEST_UNSET and len(keys) != len(set(keys)):
            raise ValueError("Setting keys must be unique")
        return keys


class _SettingChange(RequestDataModel):
    value: OptionValue
    expected_revision: Annotated[JsonInteger, Field(ge=0)]


class _UpdateSettingsRequest(RequestDataModel):
    namespace: OptionNamespace
    changes: Annotated[dict[OptionKey, _SettingChange], Field(min_length=1)]


def _setting_response(
    namespace: str, options: dict[str, ResolvedOption[Any]]
) -> dict[str, Any]:
    return {
        "namespace": namespace,
        "settings": {
            key: {
                "value": option.value,
                "revision": option.revision,
                "updated_at": option.updated_at,
            }
            for key, option in options.items()
        },
    }


class RequestListSettingsHandler(RequestHandler[_ListSettingsRequest]):
    request_model = _ListSettingsRequest
    requires_auth = True

    def handle(self, handler, request):
        with Session() as session:
            permissions = User.get_existing(session, handler.user_id).all_permissions
            if Permissions.VIEW_SETTINGS not in permissions:
                handler.conclude_request(403, {}, "Permission denied")
                return Result(code=403, user_id=handler.user_id)
        namespace = None if request.namespace is REQUEST_UNSET else request.namespace
        items = describe_settings(namespace)
        handler.conclude_request(200, {"items": items}, "Settings listed")
        return Result(
            code=0,
            target=namespace,
            data={"count": len(items)},
            user_id=handler.user_id,
        )


class RequestGetSettingsHandler(RequestHandler[_GetSettingsRequest]):
    request_model = _GetSettingsRequest
    requires_auth = True

    def handle(self, handler, request):
        namespace = request.namespace
        with Session() as session:
            permissions = User.get_existing(session, handler.user_id).all_permissions
            if Permissions.VIEW_SETTINGS not in permissions:
                handler.conclude_request(403, {}, "Permission denied")
                return Result(code=403, target=namespace, user_id=handler.user_id)
            try:
                definitions = get_setting_definitions(
                    namespace, None if request.keys is REQUEST_UNSET else request.keys
                )
            except LookupError:
                handler.conclude_request(
                    404,
                    {"namespace": namespace},
                    "Setting not found",
                )
                return Result(code=404, target=namespace, user_id=handler.user_id)
            options = read_options(session, namespace, definitions)
        handler.conclude_request(
            200, _setting_response(namespace, options), "Settings read"
        )
        return Result(
            code=0,
            target=namespace,
            data={
                "revisions": {key: option.revision for key, option in options.items()}
            },
            user_id=handler.user_id,
        )


class RequestUpdateSettingsHandler(RequestHandler[_UpdateSettingsRequest]):
    request_model = _UpdateSettingsRequest
    requires_auth = True
    rate_limit_cost = 3

    def handle(self, handler, request):
        namespace = request.namespace
        expected_revisions = {
            key: change.expected_revision for key, change in request.changes.items()
        }
        try:
            with Session() as session, session.begin():
                permissions = User.get_existing(
                    session, handler.user_id
                ).all_permissions
                if Permissions.MANAGE_SETTINGS not in permissions:
                    handler.conclude_request(403, {}, "Permission denied")
                    return Result(code=403, target=namespace, user_id=handler.user_id)
                try:
                    get_setting_definitions(namespace, list(request.changes))
                except LookupError:
                    handler.conclude_request(
                        404,
                        {"namespace": namespace},
                        "Setting not found",
                    )
                    return Result(code=404, target=namespace, user_id=handler.user_id)
                options = write_options(
                    session,
                    namespace,
                    {key: change.value for key, change in request.changes.items()},
                    expected_revisions=expected_revisions,
                    source="setting_api",
                )
                response = _setting_response(namespace, options)
        except OptionConflictError:
            handler.conclude_request(
                409,
                {"namespace": namespace},
                "Setting revision conflict; read again before retrying",
            )
            return Result(code=409, target=namespace, user_id=handler.user_id)
        except OptionValidationError:
            handler.conclude_request(
                400,
                {"namespace": namespace},
                "Invalid setting value or policy",
            )
            return Result(code=400, target=namespace, user_id=handler.user_id)
        handler.conclude_request(200, response, "Settings updated")
        return Result(
            code=0,
            target=namespace,
            data={
                "keys": sorted(options),
                "previous_revisions": expected_revisions,
                "revisions": {key: option.revision for key, option in options.items()},
            },
            user_id=handler.user_id,
        )
