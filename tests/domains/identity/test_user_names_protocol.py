import pytest

from tests.support.utils import assert_error, assert_success, permission_entry

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]


async def test_username_change_requires_login_and_escalation(
    user_client, test_user, unauthenticated_client
):
    data = {
        "user_id": test_user["user_id"],
        "username": "renamed_" + test_user["username"],
    }
    assert_error(
        await unauthenticated_client.send_request(
            "core.user.username.set", data, include_auth=False
        ),
        401,
    )
    assert_error(await user_client.send_request("core.user.username.set", data), 403)
    current = assert_success(
        await user_client.get_user_info(user_id=test_user["user_id"])
    )
    assert current["username"] == test_user["username"]


async def test_username_change_preserves_login_identity_and_audits(
    authenticated_client,
    user_factory,
    client_factory,
):
    user = await user_factory(groups=[{"group_name": "user", "start_time": 0}])
    client = await client_factory()
    assert_success(await client.login(user["username"], user["password"]))
    old_token = client.token
    assert_success(await client.elevate_token())
    new_username = "renamed_" + user["username"]
    response = await client.send_request(
        "core.user.username.set",
        {"user_id": user["user_id"].upper().replace("-", ""), "username": new_username},
    )
    assert_success(response)
    assert response["data"] == {}
    current = assert_success(
        await client.send_request(
            "core.user.info.get", {"user_id": user["user_id"]}, token=old_token
        )
    )
    assert current["username"] == new_username
    assert current["nickname"] == user["nickname"]
    assert current["user_id"] == user["user_id"]
    assert_error(await client.login(user["username"], user["password"]), 401)
    logged_in = assert_success(await client.login(new_username, user["password"]))
    assert logged_in["user_id"] == user["user_id"]
    replacement = await user_factory(username=user["username"])
    assert replacement["user_id"] != user["user_id"]
    entries = assert_success(
        await authenticated_client.view_audit_logs(filters=["core.user.username.set"])
    )["items"]
    entry = next(
        item
        for item in entries
        if item["target"] == user["user_id"] and item["result"] == 200
    )
    assert entry["user_id"] == user["user_id"]
    assert entry["data"] == {
        "target_username": user["username"],
        "new_username": new_username,
    }


async def test_nickname_change_accepts_general_token(
    authenticated_client, user_factory, client_factory
):
    user = await user_factory(permissions=[permission_entry("set_nickname")])
    client = await client_factory()
    assert_success(await client.login(user["username"], user["password"]))
    assert_success(
        await client.send_request(
            "core.user.nickname.set",
            {"user_id": user["user_id"], "nickname": "Updated"},
        )
    )
    current = assert_success(await client.get_user_info(user_id=user["user_id"]))
    assert current["nickname"] == "Updated"
    assert current["username"] == user["username"]


async def test_super_username_permission_updates_another_account(
    authenticated_client, test_user
):
    assert_success(await authenticated_client.elevate_token())
    new_username = "renamed_" + test_user["username"]
    assert_success(
        await authenticated_client.send_request(
            "core.user.username.set",
            {"user_id": test_user["user_id"], "username": new_username},
        )
    )
    current = assert_success(
        await authenticated_client.get_user_info(user_id=test_user["user_id"])
    )
    assert current["username"] == new_username
    assert current["nickname"] == test_user["nickname"]
