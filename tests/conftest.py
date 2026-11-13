"""
Pytest configuration and fixtures for CFMS test suite.
"""

import subprocess
import sys
from collections.abc import AsyncGenerator, Awaitable, Callable, Generator
from contextlib import AsyncExitStack, ExitStack

import pytest
import pytest_asyncio

from include.config import paths
from tests.support.client import CFMSTestClient
from tests.support.config import ServerTestSettings, isolated_test_runtime
from tests.support.entities import (
    directory_factory,
    document_factory,
    group_factory,
    owned_entities,
    user_factory,
)
from tests.support.server import start_server, stop_server
from tests.support.utils import assert_success

__all__ = [
    "directory_factory",
    "document_factory",
    "group_factory",
    "owned_entities",
    "user_factory",
]

pytest_plugins = ("tests.support.collection",)

_TEST_SERVER_SETTINGS = pytest.StashKey[ServerTestSettings]()


def _close_imported_runtime() -> None:
    database_module = sys.modules.get("include.database.session")
    if database_module is not None:
        database_module.engine.dispose()


def pytest_plugin_registered(plugin: object) -> None:
    if not isinstance(plugin, pytest.Config):
        return

    # This historic hook runs when the root conftest is registered, before children.
    manager = ExitStack()
    plugin.add_cleanup(manager.close)
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
        plugin.stash[_TEST_SERVER_SETTINGS] = settings
    except BaseException:
        manager.close()
        raise


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
            await test_client.connect(max_retries=1)
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
async def test_document(document_factory) -> dict:
    return await document_factory("Test Document")


@pytest_asyncio.fixture
async def test_user(user_factory) -> dict:
    return await user_factory()


@pytest_asyncio.fixture
async def test_group(group_factory) -> dict:
    return await group_factory()
