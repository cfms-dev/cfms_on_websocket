import secrets
from collections.abc import AsyncGenerator, Callable

import pytest_asyncio

from tests.support.assertions import assert_success
from tests.support.client import CFMSTestClient


@pytest_asyncio.fixture
async def owned_entities(
    authenticated_client: CFMSTestClient,
) -> AsyncGenerator[dict[str, list[str]]]:
    entities = {kind: [] for kind in ("documents", "directories", "groups", "users")}
    try:
        yield entities
    finally:
        errors = []
        for kind, identifiers in entities.items():
            for identifier in reversed(list(dict.fromkeys(identifiers))):
                try:
                    if kind == "documents":
                        response = await authenticated_client.delete_document(
                            identifier
                        )
                        assert response["code"] in (200, 404), response
                        response = await authenticated_client.purge_document(identifier)
                    elif kind == "directories":
                        response = await authenticated_client.delete_directory(
                            identifier
                        )
                        assert response["code"] in (200, 404), response
                        response = await authenticated_client.purge_directory(
                            identifier
                        )
                    elif kind == "groups":
                        response = await authenticated_client.send_request(
                            "core.group.delete", {"group_name": identifier}
                        )
                    else:
                        response = await authenticated_client.delete_user(identifier)
                    assert response["code"] in (200, 404), response
                except Exception as exc:  # noqa: BLE001 -- release all owned entities before reporting failures
                    errors.append(exc)
        if errors:
            raise ExceptionGroup("Owned entity cleanup failed", errors)


@pytest_asyncio.fixture
async def user_factory(
    authenticated_client: CFMSTestClient,
    owned_entities: dict[str, list[str]],
) -> Callable:
    async def _creator(
        username=None,
        password="TestPassword123!",
        nickname="Test User",
        groups=None,
        permissions=None,
    ):
        if not username:
            username = f"user_{secrets.token_hex(4)}"
        response = await authenticated_client.create_user(
            username=username,
            password=password,
            nickname=nickname,
            groups=groups,
            permissions=permissions,
        )
        assert_success(response)
        user_id = response["data"]["user_id"]
        owned_entities["users"].append(user_id)
        return {
            "user_id": user_id,
            "username": username,
            "password": password,
            "nickname": nickname,
        }

    return _creator


@pytest_asyncio.fixture
async def document_factory(
    authenticated_client: CFMSTestClient,
    owned_entities: dict[str, list[str]],
) -> Callable:
    async def _creator(title=None, upload_file="./pyproject.toml", folder_id=None):
        if not title:
            title = f"Doc_{secrets.token_hex(4)}"
        response = await authenticated_client.create_document(title, folder_id)
        data = assert_success(response)
        doc_id = data["document_id"]
        owned_entities["documents"].append(doc_id)

        task_id = data["task_data"]["task_id"]
        if upload_file:
            await authenticated_client.upload_file_to_server(task_id, upload_file)

        return {"document_id": doc_id, "title": title}

    return _creator


@pytest_asyncio.fixture
async def group_factory(
    authenticated_client: CFMSTestClient,
    owned_entities: dict[str, list[str]],
) -> Callable:
    async def _creator(group_name=None, permissions=None):
        if not group_name:
            group_name = f"group_{secrets.token_hex(4)}"
        if permissions is None:
            permissions = []

        response = await authenticated_client.create_group(
            group_name=group_name, permissions=permissions
        )
        assert_success(response)
        owned_entities["groups"].append(group_name)
        return {"group_name": group_name, "permissions": permissions}

    return _creator


@pytest_asyncio.fixture
async def directory_factory(
    authenticated_client: CFMSTestClient,
    owned_entities: dict[str, list[str]],
) -> Callable:
    async def create_directory(name=None, parent_id=None):
        if name is None:
            name = f"Directory_{secrets.token_hex(4)}"
        response = await authenticated_client.create_directory(name, parent_id)
        data = assert_success(response)
        folder_id = data["id"]
        owned_entities["directories"].append(folder_id)
        return {"folder_id": folder_id, "name": name, "parent_id": parent_id}

    return create_directory
