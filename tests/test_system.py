import asyncio
import ssl
import struct
import time

import pytest
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed

from tests.support.test_config import ServerTestSettings
from tests.test_client import CFMSTestClient
from tests.utils import assert_error, assert_success


def _format_ws_host(host: str) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


class TestSystemManagement:
    @pytest.mark.asyncio
    async def test_lockdown_enabled(
        self, authenticated_client: CFMSTestClient, user_factory
    ):
        # Enable lockdown
        lockdown_resp = await authenticated_client.set_lockdown(True)
        assert_success(lockdown_resp)

        try:
            # Create a regular user
            test_user = await user_factory()

            # Connect as the regular user
            user_client = CFMSTestClient()
            await user_client.connect()
            login_resp = await user_client.login(
                test_user["username"], test_user["password"]
            )
            assert_success(login_resp)

            create_resp = await user_client.create_directory("LockdownTestDir")
            try:
                assert_error(create_resp, 999)  # 999 is lockdown or access denied
            finally:
                await user_client.disconnect()
        finally:
            # Revert lockdown
            unlockdown_resp = await authenticated_client.set_lockdown(False)
            assert_success(unlockdown_resp)

    @pytest.mark.asyncio
    async def test_lockdown_broadcast_event(
        self,
        authenticated_client: CFMSTestClient,
        test_server_settings: ServerTestSettings,
    ):
        event_client = CFMSTestClient(
            host=test_server_settings.host,
            port=test_server_settings.port,
            use_ssl=test_server_settings.use_ssl,
        )
        await event_client.connect()

        try:
            lockdown_resp = await authenticated_client.set_lockdown(True)
            assert_success(lockdown_resp)

            event = await event_client.accept_event(timeout=5)
            assert event == {"event": "lockdown", "data": {"status": True}}
        finally:
            unlockdown_resp = await authenticated_client.set_lockdown(False)
            assert_success(unlockdown_resp)
            await event_client.disconnect()

    @pytest.mark.asyncio
    async def test_even_client_initiated_stream_is_rejected(
        self,
        server_process,
        test_server_settings: ServerTestSettings,
    ):
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        uri = (
            f"wss://{_format_ws_host(test_server_settings.host)}:"
            f"{test_server_settings.port}"
        )

        async with connect(uri, ssl=ssl_context, proxy=None) as websocket:
            request = b'{"action":"server_info","data":{}}'
            payload = bytearray(5 + len(request))
            struct.pack_into("!IB", payload, 0, 2, 0)
            payload[5:] = request

            await websocket.send(payload)

            with pytest.raises(ConnectionClosed) as excinfo:
                await asyncio.wait_for(websocket.recv(), timeout=5)

            assert excinfo.value.code == 1002
            assert (
                excinfo.value.reason
                == "Protocol error: invalid client-initiated stream"
            )

    @pytest.mark.asyncio
    async def test_audit_logs(self, authenticated_client: CFMSTestClient):
        # Do some actions to ensure audit logs exist
        await authenticated_client.create_directory(
            f"AuditLogFolder_{int(time.time())}"
        )

        # View audit logs
        logs_resp = await authenticated_client.view_audit_logs(count=10)
        logs_data = assert_success(logs_resp)

        assert "entries" in logs_data
        assert isinstance(logs_data["entries"], list)

        if len(logs_data["entries"]) > 0:
            first_log = logs_data["entries"][0]
            assert "action" in first_log
            assert "username" in first_log
            assert "logged_time" in first_log
