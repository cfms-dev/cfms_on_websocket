"""
Pytest configuration and fixtures for CFMS test suite.
"""

import asyncio
import os
import secrets
import subprocess
from pathlib import Path
from typing import AsyncGenerator, Callable, Generator

import pytest
import pytest_asyncio

from tests.support.server import start_server, stop_server
from tests.support.test_config import (
    TestServerSettings,
    capture_config,
    reserve_local_port,
    restore_config,
    write_test_config,
)
from tests.test_client import CFMSTestClient
from tests.utils import assert_success


@pytest.fixture(scope="session")
def protected_test_config() -> Generator[TestServerSettings, None, None]:
    """Write test config, then restore the original config at session teardown."""
    src_dir = Path("src").resolve()
    config_backup = capture_config(src_dir / "config.toml")
    port = reserve_local_port()
    old_env = {
        key: os.environ.get(key)
        for key in ("CFMS_TEST_HOST", "CFMS_TEST_PORT", "CFMS_TEST_USE_SSL")
    }

    artifacts = ["init", "app.db", "admin_password.txt"]
    try:
        settings = write_test_config(src_dir, port)
        os.environ["CFMS_TEST_HOST"] = settings.host
        os.environ["CFMS_TEST_PORT"] = str(settings.port)
        os.environ["CFMS_TEST_USE_SSL"] = "1" if settings.use_ssl else "0"

        for artifact in artifacts:
            artifact_path = src_dir / artifact
            if artifact_path.exists():
                artifact_path.unlink()

        (src_dir / "content" / "ssl").mkdir(parents=True, exist_ok=True)
        (src_dir / "content" / "logs").mkdir(parents=True, exist_ok=True)

        yield settings
    finally:
        restore_config(config_backup)
        for key, value in old_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


@pytest.fixture(scope="session")
def test_server_settings(
    protected_test_config: TestServerSettings,
) -> TestServerSettings:
    return protected_test_config


@pytest.fixture(scope="session")
def server_process(
    test_server_settings: TestServerSettings,
) -> Generator[subprocess.Popen, None, None]:
    """Start the CFMS server subprocess."""
    process, logs = start_server(test_server_settings)
    yield process
    stop_server(process, logs)


@pytest.fixture(scope="session")
def admin_credentials(server_process) -> dict:
    password_file = "src/admin_password.txt"
    if not os.path.exists(password_file):
        raise RuntimeError("Admin password file not found after server started")

    with open(password_file, "r", encoding="utf-8") as f:
        password = f.read().strip()
    if not password:
        raise RuntimeError("Admin password file is empty")
    return {"username": "admin", "password": password}


@pytest_asyncio.fixture
async def client(
    server_process, test_server_settings: TestServerSettings
) -> AsyncGenerator[CFMSTestClient, None]:
    test_client = CFMSTestClient(
        host=test_server_settings.host,
        port=test_server_settings.port,
        use_ssl=test_server_settings.use_ssl,
    )
    for attempt in range(5):
        try:
            await test_client.connect()
            break
        except (ConnectionRefusedError, TimeoutError, OSError) as e:
            if attempt == 4:
                raise RuntimeError(f"Failed to connect to server: {e}")
            await asyncio.sleep(1)
    yield test_client
    try:
        await test_client.disconnect()
    except Exception:
        pass


@pytest_asyncio.fixture
async def authenticated_client(
    client: CFMSTestClient, admin_credentials: dict
) -> CFMSTestClient:
    response = await client.login(
        admin_credentials["username"], admin_credentials["password"]
    )
    assert response.get("code") == 200, f"Login failed: {response}"
    return client


@pytest_asyncio.fixture
async def unauthenticated_client(
    server_process, test_server_settings: TestServerSettings
) -> AsyncGenerator[CFMSTestClient, None]:
    test_client = CFMSTestClient(
        host=test_server_settings.host,
        port=test_server_settings.port,
        use_ssl=test_server_settings.use_ssl,
    )
    for attempt in range(5):
        try:
            await test_client.connect()
            break
        except (ConnectionRefusedError, TimeoutError, OSError) as e:
            if attempt == 4:
                raise RuntimeError(f"Failed to connect to server: {e}")
            await asyncio.sleep(1)
    yield test_client
    try:
        await test_client.disconnect()
    except Exception:
        pass


@pytest_asyncio.fixture
async def user_factory(
    authenticated_client: CFMSTestClient,
) -> AsyncGenerator[Callable, None]:
    created_users = []

    async def _creator(
        username=None, password="TestPassword123!", nickname="Test User"
    ):
        if not username:
            username = f"user_{secrets.token_hex(4)}"
        response = await authenticated_client.create_user(
            username=username, password=password, nickname=nickname
        )
        assert_success(response)
        created_users.append(username)
        return {"username": username, "password": password, "nickname": nickname}

    yield _creator

    for user in created_users:
        try:
            await authenticated_client.delete_user(user)
        except Exception:
            pass


@pytest_asyncio.fixture
async def document_factory(
    authenticated_client: CFMSTestClient,
) -> AsyncGenerator[Callable, None]:
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

    for doc_id in created_docs:
        try:
            await authenticated_client.delete_document(doc_id)
        except Exception:
            pass


@pytest_asyncio.fixture
async def group_factory(
    authenticated_client: CFMSTestClient,
) -> AsyncGenerator[Callable, None]:
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

    for group_name in created_groups:
        try:
            await authenticated_client.send_request(
                "delete_group", {"group_name": group_name}
            )
        except Exception:
            pass


@pytest_asyncio.fixture
async def test_document(document_factory) -> dict:
    return await document_factory("Test Document")


@pytest_asyncio.fixture
async def test_user(user_factory) -> dict:
    return await user_factory()


@pytest_asyncio.fixture
async def test_group(group_factory) -> dict:
    return await group_factory()
