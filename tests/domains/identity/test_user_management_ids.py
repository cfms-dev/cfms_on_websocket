import uuid

import pytest

from tests.support.utils import assert_error, assert_success

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]


async def test_discover_and_manage_user_by_id(authenticated_client, test_user):
    info = assert_success(
        await authenticated_client.get_user_info(username=test_user["username"])
    )
    user_id = info["user_id"]
    assert user_id == test_user["user_id"]
    users = assert_success(await authenticated_client.list_users())["users"]
    assert any(item["user_id"] == user_id for item in users)

    assert_success(
        await authenticated_client.send_request(
            "core.user.nickname.set",
            {"user_id": user_id.upper(), "nickname": "Updated nickname"},
        )
    )
    updated = assert_success(await authenticated_client.get_user_info(user_id=user_id))
    assert updated["nickname"] == "Updated nickname"
    assert updated["username"] == test_user["username"]
    assert updated["user_id"] == user_id
    status = assert_success(
        await authenticated_client.update_user_status(user_id, "disabled")
    )
    assert status["user_id"] == user_id
    assert status["username"] == test_user["username"]
    assert_success(await authenticated_client.update_user_status(user_id, "active"))

    entries = assert_success(
        await authenticated_client.view_audit_logs(
            filters=["core.user.nickname.set", "core.user.create"]
        )
    )["items"]
    for action in ("core.user.nickname.set", "core.user.create"):
        entry = next(
            item
            for item in entries
            if item["action"] == action and item["target"] == user_id
        )
        assert entry["user_id"] == authenticated_client.user_id
        assert entry["data"]["target_username"] == test_user["username"]


async def test_uuid_shaped_username_does_not_override_selector(
    authenticated_client, user_factory
):
    first = await user_factory()
    named = await user_factory(username=first["user_id"])
    by_name = assert_success(
        await authenticated_client.get_user_info(username=first["user_id"])
    )
    by_id = assert_success(
        await authenticated_client.get_user_info(user_id=first["user_id"])
    )
    assert by_name["user_id"] == named["user_id"]
    assert by_id["user_id"] == first["user_id"]


async def test_stale_id_cannot_manage_same_named_replacement(
    authenticated_client, user_factory
):
    old = await user_factory()
    assert_success(await authenticated_client.delete_user(old["user_id"]))
    replacement = await user_factory(username=old["username"])
    assert replacement["user_id"] != old["user_id"]
    assert_error(await authenticated_client.get_user_info(user_id=old["user_id"]), 404)
    assert_error(await authenticated_client.delete_user(old["user_id"]), 404)
    assert_error(
        await authenticated_client.change_user_permissions(old["user_id"], []), 404
    )
    assert_error(
        await authenticated_client.send_request(
            "core.user.nickname.set",
            {"user_id": old["user_id"], "nickname": "Wrong account"},
        ),
        400,
    )
    assert_success(await authenticated_client.elevate_token())
    assert_error(
        await authenticated_client.send_request(
            "core.user.password.set",
            {"user_id": old["user_id"], "new_passwd": "UpdatedPassword456!"},
        ),
        404,
    )
    info = assert_success(
        await authenticated_client.get_user_info(user_id=replacement["user_id"])
    )
    assert info["nickname"] == replacement["nickname"]
    assert info["username"] == old["username"]


async def test_deleted_user_dacl_does_not_grant_access_to_same_named_replacement(
    authenticated_client,
    user_factory,
    document_factory,
    client_factory,
):
    old = await user_factory()
    document = await document_factory()
    assert_success(
        await authenticated_client.set_document_dacl(
            document["document_id"],
            f'inherit off; allow [READ_METADATA] to user("{old["user_id"]}");',
        )
    )
    assert_success(await authenticated_client.delete_user(old["user_id"]))
    replacement = await user_factory(username=old["username"])
    replacement_client = await client_factory()
    assert_success(
        await replacement_client.login(replacement["username"], replacement["password"])
    )
    assert_error(
        await replacement_client.get_document_info(document["document_id"]),
        403,
    )


async def test_self_protection_compares_uuid_values(authenticated_client):
    user_id = authenticated_client.user_id.upper().replace("-", "")
    assert_error(await authenticated_client.delete_user(user_id), 400)
    assert_error(
        await authenticated_client.update_user_status(user_id, "disabled"), 400
    )


async def test_administrator_manages_keyring_by_user_id(
    authenticated_client, user_client, test_user
):
    key = assert_success(
        await authenticated_client.upload_keyring(
            "encrypted-content", user_id=test_user["user_id"]
        )
    )
    own_keys = assert_success(await user_client.list_keyrings())["keys"]
    admin_keys = assert_success(
        await authenticated_client.list_keyrings(user_id=test_user["user_id"])
    )["keys"]
    assert [item["id"] for item in own_keys] == [key["id"]]
    assert admin_keys == own_keys


@pytest.mark.parametrize(
    ("action", "extra"),
    [("core.user.key.upload", {"content": "encrypted"}), ("core.user.key.list", {})],
)
async def test_keyring_authorizes_before_target_lookup(
    low_privilege_client, test_user, action, extra
):
    responses = []
    for user_id in (test_user["user_id"], str(uuid.uuid4())):
        responses.append(
            await low_privilege_client.send_request(
                action, {**extra, "user_id": user_id}
            )
        )
    for response in responses:
        assert_error(response, 403)
        assert response["data"] == {}


async def test_administrator_reset_uses_id_and_audits_actor(
    authenticated_client, user_client, test_user
):
    assert_success(await authenticated_client.elevate_token())
    response = await authenticated_client.send_request(
        "core.user.password.set",
        {
            "user_id": test_user["user_id"],
            "new_passwd": "UpdatedPassword456!",
        },
    )
    assert_success(response)
    assert_error(await user_client.refresh_token(), 401)
    assert_success(
        await user_client.login(test_user["username"], "UpdatedPassword456!")
    )
    entries = assert_success(
        await authenticated_client.view_audit_logs(filters=["core.user.password.set"])
    )["items"]
    entry = next(item for item in entries if item["target"] == test_user["user_id"])
    assert entry["user_id"] == authenticated_client.user_id
    assert entry["data"] == {"target_username": test_user["username"]}
