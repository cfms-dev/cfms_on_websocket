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
            "rename_user", {"user_id": user_id.upper(), "nickname": "Updated nickname"}
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
            filters=["rename_user", "create_user"]
        )
    )["items"]
    for action in ("rename_user", "create_user"):
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
            "rename_user", {"user_id": old["user_id"], "nickname": "Wrong account"}
        ),
        400,
    )
    assert_error(
        await authenticated_client.send_request(
            "set_passwd",
            {"user_id": old["user_id"], "new_passwd": "UpdatedPassword456!"},
        ),
        404,
    )
    info = assert_success(
        await authenticated_client.get_user_info(user_id=replacement["user_id"])
    )
    assert info["nickname"] == replacement["nickname"]
    assert info["username"] == old["username"]


async def test_deleted_user_access_listing_hides_orphaned_grants(
    authenticated_client,
    user_factory,
    document_factory,
):
    old = await user_factory()
    document = await document_factory()
    assert_success(
        await authenticated_client.grant_access(
            entity_type="user",
            entity_identifier=old["user_id"],
            target_type="document",
            target_identifier=document["document_id"],
            access_types=["read"],
            start_time=0,
        )
    )
    assert_success(await authenticated_client.delete_user(old["user_id"]))
    missing = assert_success(
        await authenticated_client.view_access_entries(
            object_type="user",
            object_identifier=old["user_id"],
        )
    )
    assert missing["items"] == []
    assert missing["has_more"] is False
    replacement = await user_factory(username=old["username"])
    current = assert_success(
        await authenticated_client.view_access_entries(
            object_type="user",
            object_identifier=replacement["user_id"],
        )
    )
    assert current["items"] == []


async def test_self_protection_compares_uuid_values(authenticated_client):
    user_id = authenticated_client.user_id.upper().replace("-", "")
    assert_error(await authenticated_client.delete_user(user_id), 400)
    assert_error(
        await authenticated_client.update_user_status(user_id, "disabled"), 400
    )


async def test_block_cursor_binds_canonical_user_id(
    authenticated_client, test_user, user_factory
):
    user_id = test_user["user_id"]
    other = await user_factory()
    for block_type in ("read", "write"):
        block = assert_success(
            await authenticated_client.block_user(user_id, "all", [block_type])
        )
        assert block["user_id"] == user_id
    first = assert_success(
        await authenticated_client.send_request(
            "list_user_blocks",
            {"user_id": user_id.upper().replace("-", ""), "page_size": 1},
        )
    )
    data = {"user_id": user_id, "page_size": 1, "cursor": first["next_cursor"]}
    second = assert_success(
        await authenticated_client.send_request("list_user_blocks", data)
    )
    assert second["items"][0]["block_id"] != first["items"][0]["block_id"]
    assert second["items"][0]["user_id"] == user_id
    assert_error(
        await authenticated_client.send_request(
            "list_user_blocks", {**data, "user_id": other["user_id"]}
        ),
        400,
    )
    missing = assert_success(
        await authenticated_client.send_request(
            "list_user_blocks", {"user_id": str(uuid.uuid4())}
        )
    )
    assert missing["items"] == []


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
    [("upload_user_key", {"content": "encrypted"}), ("list_user_keys", {})],
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
    assert responses[0]["message"] == responses[1]["message"]


async def test_administrator_reset_uses_id_and_audits_actor(
    authenticated_client, user_client, test_user
):
    response = await authenticated_client.send_request(
        "set_passwd",
        {
            "user_id": test_user["user_id"],
            "old_passwd": None,
            "new_passwd": "UpdatedPassword456!",
        },
    )
    assert_success(response)
    assert_error(await user_client.refresh_token(), 401)
    assert_success(
        await user_client.login(test_user["username"], "UpdatedPassword456!")
    )
    entries = assert_success(
        await authenticated_client.view_audit_logs(filters=["set_passwd"])
    )["items"]
    entry = next(item for item in entries if item["target"] == test_user["user_id"])
    assert entry["user_id"] == authenticated_client.user_id
    assert entry["data"] == {"target_username": test_user["username"]}
