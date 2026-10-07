"""Keyring behavior for an isolated user's keys."""

import pytest

from tests.support.client import CFMSTestClient
from tests.support.utils import assert_error, assert_success


class TestKeyringOperations:
    @pytest.mark.asyncio
    async def test_upload_keyring(self, user_client: CFMSTestClient):
        data = assert_success(
            await user_client.upload_keyring(
                key_content="encrypted_dek_value_abc123", label="test-key"
            )
        )

        assert data["id"]

    @pytest.mark.asyncio
    async def test_get_keyring(self, user_client: CFMSTestClient):
        key_id = assert_success(
            await user_client.upload_keyring(
                key_content="get_test_content", label="get-test"
            )
        )["id"]

        data = assert_success(await user_client.get_keyring(key_id))

        assert data["key_id"] == key_id
        assert data["key_content"] == "get_test_content"
        assert data["label"] == "get-test"

    @pytest.mark.asyncio
    async def test_get_nonexistent_keyring(self, user_client: CFMSTestClient):
        response = await user_client.get_keyring("nonexistent_key_id_xyz")

        assert_error(response, 404)

    @pytest.mark.asyncio
    async def test_delete_keyring(self, user_client: CFMSTestClient):
        key_id = assert_success(
            await user_client.upload_keyring(key_content="delete_test_content")
        )["id"]

        response = await user_client.delete_keyring(key_id)

        assert_success(response)
        assert_error(await user_client.get_keyring(key_id), 404)

    @pytest.mark.asyncio
    async def test_list_keyrings(self, user_client: CFMSTestClient):
        key_id = assert_success(
            await user_client.upload_keyring(
                key_content="list_test_content", label="list-test"
            )
        )["id"]

        data = assert_success(await user_client.list_keyrings())

        assert data["offset"] == 0
        assert data["total"] == 1
        assert data["has_more"] is False
        assert [key["id"] for key in data["keys"]] == [key_id]
        assert "key_content" not in data["keys"][0]

    @pytest.mark.asyncio
    async def test_set_preference_dek(self, user_client: CFMSTestClient):
        key_id = assert_success(
            await user_client.upload_keyring(key_content="preference_dek_content")
        )["id"]

        response = await user_client.set_preference_keyring(key_id)

        assert_success(response)
        keys = assert_success(await user_client.list_keyrings())["keys"]
        assert {key["id"]: key["is_preference_dek"] for key in keys} == {key_id: True}

    @pytest.mark.asyncio
    async def test_set_preference_dek_replaces_previous(
        self,
        user_client: CFMSTestClient,
    ):
        first_id = assert_success(
            await user_client.upload_keyring(key_content="first_dek")
        )["id"]
        second_id = assert_success(
            await user_client.upload_keyring(key_content="second_dek")
        )["id"]
        assert_success(await user_client.set_preference_keyring(first_id))
        initial_keys = assert_success(await user_client.list_keyrings())["keys"]
        assert {key["id"]: key["is_preference_dek"] for key in initial_keys} == {
            first_id: True,
            second_id: False,
        }

        response = await user_client.set_preference_keyring(second_id)

        assert_success(response)
        keys = assert_success(await user_client.list_keyrings())["keys"]
        assert {key["id"]: key["is_preference_dek"] for key in keys} == {
            first_id: False,
            second_id: True,
        }

    @pytest.mark.asyncio
    async def test_preference_dek_returned_on_login(
        self,
        client: CFMSTestClient,
        test_user,
        user_client: CFMSTestClient,
    ):
        key_id = assert_success(
            await user_client.upload_keyring(key_content="login_dek_content")
        )["id"]
        assert_success(await user_client.set_preference_keyring(key_id))

        data = assert_success(
            await client.login(test_user["username"], test_user["password"])
        )

        assert data["preference_dek"]["key_id"] == key_id
        assert data["preference_dek"]["key_content"] == "login_dek_content"

    @pytest.mark.asyncio
    async def test_no_preference_dek_not_in_login(
        self,
        client: CFMSTestClient,
        test_user,
    ):
        data = assert_success(
            await client.login(test_user["username"], test_user["password"])
        )

        assert "preference_dek" not in data


class TestKeyringWithoutAuth:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("action", "data"),
        [
            pytest.param("upload_user_key", {"content": "test"}, id="upload"),
            pytest.param("get_user_key", {"id": "someid"}, id="get"),
            pytest.param("delete_user_key", {"id": "someid"}, id="delete"),
            pytest.param("list_user_keys", {}, id="list"),
            pytest.param(
                "set_user_preference_dek", {"id": "someid"}, id="set-preference"
            ),
        ],
    )
    async def test_keyring_operations_require_authentication(
        self,
        client: CFMSTestClient,
        action,
        data,
    ):
        response = await client.send_request(action, data, include_auth=False)

        assert_error(response, 401)
