"""
Pytest configuration and fixtures for CFMS test suite.
"""

import asyncio
import os
import secrets
import subprocess
import sys
import threading
import time
from typing import AsyncGenerator, Callable, Generator

import pytest
import pytest_asyncio

from tests.test_client import CFMSTestClient
from tests.utils import assert_success


def log_server_output(process: subprocess.Popen, log_dir: str = "test_logs"):
    os.makedirs(log_dir, exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    stdout_path = os.path.join(log_dir, f"server_stdout_{timestamp}.log")
    stderr_path = os.path.join(log_dir, f"server_stderr_{timestamp}.log")

    stdout_file = open(stdout_path, "w", encoding="utf-8", buffering=1)
    stderr_file = open(stderr_path, "w", encoding="utf-8", buffering=1)

    stop_event = threading.Event()

    def read_stream(stream, output_file):
        try:
            while not stop_event.is_set():
                line = stream.readline()
                if not line:
                    break
                try:
                    output_file.write(line)
                    output_file.flush()
                except (ValueError, OSError):
                    break
        except Exception:
            pass

    stdout_thread = threading.Thread(
        target=read_stream, args=(process.stdout, stdout_file), daemon=True
    )
    stderr_thread = threading.Thread(
        target=read_stream, args=(process.stderr, stderr_file), daemon=True
    )

    stdout_thread.start()
    stderr_thread.start()

    return stdout_thread, stderr_thread, stdout_file, stderr_file, stop_event


@pytest.fixture(scope="session")
def test_config():
    """Prepare and clean up configuration and data for testing."""
    src_config_file = "src/config.toml"

    if not os.path.exists(src_config_file):
        import shutil

        if not os.path.exists("src/config.toml.sample"):
            raise RuntimeError("Config sample file not found: src/config.toml.sample")
        shutil.copy("src/config.toml.sample", src_config_file)

    with open(src_config_file, "r", encoding="utf-8") as f:
        config_content = f.read()

    config_changes = {
        "debug = false": "debug = true",
        "enable_passwd_force_expiration = true": "enable_passwd_force_expiration = false",
        "require_passwd_enforcement_changes = true": "require_passwd_enforcement_changes = false",
        "dualstack_ipv6 = true": "dualstack_ipv6 = false",
    }
    for old, new in config_changes.items():
        config_content = config_content.replace(old, new)

    with open(src_config_file, "w", encoding="utf-8") as f:
        f.write(config_content)

    artifacts = ["init", "app.db", "admin_password.txt"]
    for artifact in artifacts:
        artifact_path = os.path.join("src", artifact)
        if os.path.exists(artifact_path):
            os.remove(artifact_path)

    os.makedirs("src/content/ssl", exist_ok=True)
    os.makedirs("src/content/logs", exist_ok=True)

    yield
    # Could potentially clean up app.db here if desired, but helps with post-mortem debug if left


@pytest.fixture(scope="session")
def server_process(test_config) -> Generator[subprocess.Popen, None, None]:
    """Start the CFMS server subprocess."""
    print("\n[TEST SETUP] Starting CFMS server...", file=sys.stderr)

    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    process = subprocess.Popen(
        [sys.executable, "main.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        bufsize=1,
        cwd=os.path.join(os.getcwd(), "src"),
        env=env,
    )

    stdout_thread, stderr_thread, stdout_file, stderr_file, stop_event = (
        log_server_output(process, "test_logs")
    )
    process._log_threads = (stdout_thread, stderr_thread, stop_event)
    process._log_files = (stdout_file, stderr_file)

    max_wait = 20
    waited = 0
    while waited < max_wait:
        time.sleep(0.5)
        waited += 0.5
        if process.poll() is not None:
            break
        if os.path.exists("src/admin_password.txt"):
            time.sleep(1)  # wait for full startup
            break

    if not os.path.exists("src/admin_password.txt"):
        process.terminate()
        process.wait(timeout=3)
        raise RuntimeError(
            f"Server initialization timed out or crashed after {max_wait}s."
        )

    print("[TEST SETUP] Server started successfully!", file=sys.stderr)
    yield process

    # Cleanup
    print("\n[TEST CLEANUP] Shutting down server...", file=sys.stderr)
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()

    stop_event.set()
    for pipe in (process.stdout, process.stderr):
        try:
            if pipe:
                pipe.close()
        except:
            pass

    stdout_thread.join(timeout=2)
    stderr_thread.join(timeout=2)
    stdout_file.close()
    stderr_file.close()


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
async def client(server_process) -> AsyncGenerator[CFMSTestClient, None]:
    test_client = CFMSTestClient()
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
    server_process,
) -> AsyncGenerator[CFMSTestClient, None]:
    test_client = CFMSTestClient()
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
