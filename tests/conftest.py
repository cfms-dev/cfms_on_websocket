"""
Pytest configuration and fixtures for CFMS test suite.
"""

import secrets
import subprocess
import sys
from collections.abc import AsyncGenerator, Awaitable, Callable, Generator
from contextlib import AsyncExitStack, ExitStack

import pytest
import pytest_asyncio

from include.config import paths
from tests.support.client import CFMSTestClient
from tests.support.config import (
    ServerTestSettings,
    isolated_test_runtime,
)
from tests.support.server import start_server, stop_server
from tests.support.utils import assert_success

_TEST_CONFIG_MANAGER = pytest.StashKey[ExitStack]()
_TEST_SERVER_SETTINGS = pytest.StashKey[ServerTestSettings]()


def _close_imported_runtime() -> None:
    settings_module = sys.modules.get("include.config.settings")
    database_module = sys.modules.get("include.database.session")
    try:
        if settings_module is not None:
            settings_module.global_config.stop()
    finally:
        if database_module is not None:
            database_module.engine.dispose()


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_sessionstart(session: pytest.Session) -> Generator[None]:
    manager = ExitStack()
    try:
        settings = manager.enter_context(isolated_test_runtime())
        patch = pytest.MonkeyPatch()
        manager.callback(patch.undo)
        patch.setattr(paths, "EXECUTABLE_ABSPATH", settings.src_dir)
        patch.setattr(paths, "PROJECT_ABSPATH", settings.src_dir.parent)
        patch.setattr(
            paths, "EXTENSION_ROOT", settings.src_dir / "include" / "extensions"
        )
        manager.callback(_close_imported_runtime)
        session.config.stash[_TEST_CONFIG_MANAGER] = manager
        session.config.stash[_TEST_SERVER_SETTINGS] = settings
        yield
    except BaseException:
        manager.close()
        raise


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_sessionfinish(
    session: pytest.Session,
    exitstatus: int | pytest.ExitCode,
) -> Generator[None]:
    try:
        yield
    finally:
        manager = session.config.stash.get(_TEST_CONFIG_MANAGER, None)
        if manager is not None:
            manager.close()


@pytest.fixture(scope="session")
def protected_test_config(
    request: pytest.FixtureRequest,
) -> ServerTestSettings:
    return request.config.stash[_TEST_SERVER_SETTINGS]


@pytest.fixture(scope="session")
def test_server_settings(
    protected_test_config: ServerTestSettings,
) -> ServerTestSettings:
    return protected_test_config


@pytest.fixture(scope="session")
def server_process(
    test_server_settings: ServerTestSettings,
) -> Generator[subprocess.Popen]:
    """Start the CFMS server subprocess."""
    process, logs = start_server(test_server_settings)
    try:
        yield process
    finally:
        stop_server(process, logs)


@pytest.fixture(scope="session")
def admin_credentials(server_process, test_server_settings: ServerTestSettings) -> dict:
    password_file = test_server_settings.src_dir / "admin_password.txt"
    if not password_file.is_file():
        raise RuntimeError("Admin password file not found after server started")

    password = password_file.read_text(encoding="utf-8").strip()
    if not password:
        raise RuntimeError("Admin password file is empty")
    return {"username": "admin", "password": password}


@pytest_asyncio.fixture
async def client_factory(
    server_process, test_server_settings: ServerTestSettings
) -> AsyncGenerator[Callable[[], Awaitable[CFMSTestClient]]]:
    async with AsyncExitStack() as connections:

        async def create_client() -> CFMSTestClient:
            test_client = CFMSTestClient(
                host=test_server_settings.host,
                port=test_server_settings.port,
                use_ssl=test_server_settings.use_ssl,
            )
            connections.push_async_callback(test_client.disconnect)
            await test_client.connect()
            return test_client

        yield create_client


@pytest_asyncio.fixture
async def client(client_factory) -> CFMSTestClient:
    return await client_factory()


@pytest_asyncio.fixture
async def authenticated_client(
    client_factory, admin_credentials: dict
) -> CFMSTestClient:
    client = await client_factory()
    response = await client.login(
        admin_credentials["username"], admin_credentials["password"]
    )
    assert response.get("code") == 200, f"Login failed: {response}"
    return client


@pytest_asyncio.fixture
async def unauthenticated_client(
    client_factory,
) -> CFMSTestClient:
    return await client_factory()


@pytest_asyncio.fixture
async def user_client(test_user: dict, client_factory) -> CFMSTestClient:
    client = await client_factory()
    assert_success(await client.login(test_user["username"], test_user["password"]))
    return client


@pytest_asyncio.fixture
async def low_privilege_client(
    unauthenticated_client: CFMSTestClient,
    user_factory,
) -> CFMSTestClient:
    user = await user_factory()
    response = await unauthenticated_client.login(user["username"], user["password"])
    assert_success(response)
    return unauthenticated_client


@pytest_asyncio.fixture
async def user_factory(
    authenticated_client: CFMSTestClient,
) -> AsyncGenerator[Callable]:
    created_users = []

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
        created_users.append(username)
        return {"username": username, "password": password, "nickname": nickname}

    yield _creator

    errors = []
    for user in reversed(created_users):
        try:
            response = await authenticated_client.delete_user(user)
            assert response["code"] in (200, 404), response
        except Exception as exc:  # noqa: BLE001 -- attempt cleanup of every owned user
            errors.append(exc)
    if errors:
        raise ExceptionGroup("User cleanup failed", errors)


@pytest_asyncio.fixture
async def document_factory(
    authenticated_client: CFMSTestClient,
) -> AsyncGenerator[Callable]:
    created_docs = []

    async def _creator(title=None, upload_file="./pyproject.toml", folder_id=None):
        if not title:
            title = f"Doc_{secrets.token_hex(4)}"
        response = await authenticated_client.create_document(title, folder_id)
        data = assert_success(response)
        doc_id = data["document_id"]
        created_docs.append(doc_id)

        task_id = data["task_data"]["task_id"]
        if upload_file:
            await authenticated_client.upload_file_to_server(task_id, upload_file)

        return {"document_id": doc_id, "title": title}

    yield _creator

    errors = []
    for doc_id in reversed(created_docs):
        try:
            response = await authenticated_client.delete_document(doc_id)
            assert response["code"] in (200, 404), response
            response = await authenticated_client.purge_document(doc_id)
            assert response["code"] in (200, 404), response
        except Exception as exc:  # noqa: BLE001 -- attempt cleanup of every owned document
            errors.append(exc)
    if errors:
        raise ExceptionGroup("Document cleanup failed", errors)


@pytest_asyncio.fixture
async def group_factory(
    authenticated_client: CFMSTestClient,
) -> AsyncGenerator[Callable]:
    created_groups = []

    async def _creator(group_name=None, permissions=None):
        if not group_name:
            group_name = f"group_{secrets.token_hex(4)}"
        if permissions is None:
            permissions = []

        response = await authenticated_client.create_group(
            group_name=group_name, permissions=permissions
        )
        assert_success(response)
        created_groups.append(group_name)
        return {"group_name": group_name, "permissions": permissions}

    yield _creator

    errors = []
    for group_name in reversed(created_groups):
        try:
            response = await authenticated_client.send_request(
                "delete_group", {"group_name": group_name}
            )
            assert response["code"] in (200, 404), response
        except Exception as exc:  # noqa: BLE001 -- attempt cleanup of every owned group
            errors.append(exc)
    if errors:
        raise ExceptionGroup("Group cleanup failed", errors)


@pytest_asyncio.fixture
async def directory_factory(
    authenticated_client: CFMSTestClient,
) -> AsyncGenerator[Callable]:
    created_directories = []

    async def create_directory(name=None, parent_id=None):
        if name is None:
            name = f"Directory_{secrets.token_hex(4)}"
        response = await authenticated_client.create_directory(name, parent_id)
        data = assert_success(response)
        folder_id = data["id"]
        created_directories.append(folder_id)
        return {"folder_id": folder_id, "name": name, "parent_id": parent_id}

    yield create_directory

    errors = []
    for folder_id in reversed(created_directories):
        try:
            response = await authenticated_client.delete_directory(folder_id)
            assert response["code"] in (200, 404), response
            response = await authenticated_client.purge_directory(folder_id)
            assert response["code"] in (200, 404), response
        except Exception as exc:  # noqa: BLE001 -- attempt cleanup of every owned directory
            errors.append(exc)
    if errors:
        raise ExceptionGroup("Directory cleanup failed", errors)


@pytest_asyncio.fixture
async def test_document(document_factory) -> dict:
    return await document_factory("Test Document")


@pytest_asyncio.fixture
async def test_user(user_factory) -> dict:
    return await user_factory()


@pytest_asyncio.fixture
async def test_group(group_factory) -> dict:
    return await group_factory()
