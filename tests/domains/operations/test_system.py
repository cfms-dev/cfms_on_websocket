import asyncio
import ssl
import struct
import time
from importlib.metadata import version as distribution_version

import pytest
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed

from include.config.constants import CORE_VERSION
from tests.support.client import CFMSTestClient
from tests.support.config import ServerTestSettings
from tests.support.utils import assert_error, assert_success, permission_entry


def _format_ws_host(host: str) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


def _collect_keys(value) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {
            nested_key
            for nested_value in value.values()
            for nested_key in _collect_keys(nested_value)
        }
    if isinstance(value, list):
        return {
            nested_key
            for nested_value in value
            for nested_key in _collect_keys(nested_value)
        }
    return set()


class TestSystemManagement:
    @pytest.mark.asyncio
    async def test_diagnostics_requires_authentication(self, client: CFMSTestClient):
        response = await client.send_request("diagnostics", include_auth=False)
        assert_error(response, 401)

    @pytest.mark.asyncio
    async def test_diagnostics_requires_dedicated_permission(
        self,
        authenticated_client: CFMSTestClient,
        low_privilege_client: CFMSTestClient,
    ):
        response = await low_privilege_client.diagnostics()
        assert_error(response, 403)

        audit_items = assert_success(
            await authenticated_client.view_audit_logs(filters=["diagnostics"])
        )["items"]
        denied = next(
            item
            for item in audit_items
            if item["username"] == low_privilege_client.username
        )
        assert denied["result"] == 403
        assert denied["data"] is None

    @pytest.mark.asyncio
    async def test_diagnostics_returns_allowlisted_snapshot_and_audits_access(
        self, authenticated_client: CFMSTestClient
    ):
        diagnostics = assert_success(await authenticated_client.diagnostics())

        assert set(diagnostics) == {
            "schema_version",
            "server",
            "runtime",
            "component_versions",
            "database",
            "providers",
            "extensions",
            "extension_flags",
            "lockdown",
        }
        assert diagnostics["schema_version"] == 1
        assert diagnostics["server"] == {
            "server_name": "CFMS WebSocket Server",
            "core_version": CORE_VERSION.original,
            "protocol_version": 25,
            "debug_configured": True,
        }
        assert set(diagnostics["runtime"]) == {
            "python_implementation",
            "python_version",
            "openssl_version",
            "operating_system",
            "operating_system_release",
            "architecture",
        }
        assert all(isinstance(value, str) for value in diagnostics["runtime"].values())
        expected_components = {
            component: distribution_version(distribution)
            for component, distribution in {
                "cryptography": "cryptography",
                "orjson": "orjson",
                "pluggy": "pluggy",
                "pydantic": "pydantic",
                "sqlalchemy": "SQLAlchemy",
                "websockets": "websockets",
            }.items()
        }
        assert diagnostics["component_versions"] == expected_components
        assert diagnostics["database"] == {
            "dialect": "sqlite",
            "driver": "pysqlite",
        }
        assert diagnostics["providers"] == {
            "storage": "local",
            "caching": "memory",
            "event_bus": "local",
            "rate_limit": "memory",
        }
        assert diagnostics["extensions"][0] == {
            "identifier": "builtin",
            "name": "CFMS Built-in Extension",
            "version": "0.6.0",
        }
        assert isinstance(diagnostics["extension_flags"], list)
        assert diagnostics["lockdown"] == {"enabled": False, "reason": None}

        forbidden_keys = {
            "path",
            "hostname",
            "host",
            "ip",
            "ip_address",
            "port",
            "url",
            "database_name",
            "bucket",
            "credentials",
            "password",
            "secret",
            "secret_key",
            "certificate",
            "environment",
            "pid",
            "logs",
            "traceback",
            "users",
        }
        assert _collect_keys(diagnostics).isdisjoint(forbidden_keys)

        audit_items = assert_success(
            await authenticated_client.view_audit_logs(filters=["diagnostics"])
        )["items"]
        assert audit_items[0]["action"] == "diagnostics"
        assert audit_items[0]["result"] == 0
        assert audit_items[0]["data"] is None

    @pytest.mark.asyncio
    async def test_diagnostics_requires_lockdown_bypass(
        self,
        authenticated_client: CFMSTestClient,
        test_server_settings: ServerTestSettings,
        user_factory,
    ):
        user = await user_factory()
        assert_success(
            await authenticated_client.change_user_permissions(
                user["username"], [permission_entry("diagnostics")]
            )
        )
        diagnostics_client = CFMSTestClient(
            host=test_server_settings.host,
            port=test_server_settings.port,
            use_ssl=test_server_settings.use_ssl,
        )
        await diagnostics_client.connect()
        assert_success(
            await diagnostics_client.login(user["username"], user["password"])
        )

        try:
            assert_success(
                await authenticated_client.set_lockdown(True, "Scheduled maintenance")
            )
            lockdown_error = assert_error(
                await diagnostics_client.diagnostics(),
                999,
            )
            assert lockdown_error["data"] == {
                "status": True,
                "reason": "Scheduled maintenance",
            }
            admin_diagnostics = assert_success(await authenticated_client.diagnostics())
            assert admin_diagnostics["lockdown"] == {
                "enabled": True,
                "reason": "Scheduled maintenance",
            }
        finally:
            assert_success(await authenticated_client.set_lockdown(False))
            await diagnostics_client.disconnect()

    @pytest.mark.asyncio
    async def test_lockdown_enabled(
        self, authenticated_client: CFMSTestClient, user_factory
    ):
        # Enable lockdown
        lockdown_resp = await authenticated_client.set_lockdown(
            True, "Scheduled maintenance"
        )
        assert assert_success(lockdown_resp) == {
            "status": True,
            "reason": "Scheduled maintenance",
        }

        corrected_reason = "Corrected maintenance window"
        assert assert_success(
            await authenticated_client.set_lockdown(True, corrected_reason)
        ) == {
            "status": True,
            "reason": corrected_reason,
        }

        audit_items = assert_success(
            await authenticated_client.view_audit_logs(filters=["lockdown"])
        )["items"]
        assert audit_items[0]["data"]["reason_change"] == {
            "previous": "Scheduled maintenance",
            "current": corrected_reason,
        }

        server_info = assert_success(await authenticated_client.server_info())
        assert server_info["lockdown"] is True
        assert server_info["lockdown_reason"] == corrected_reason

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
                error = assert_error(create_resp, 999)
                assert error["data"] == {
                    "status": True,
                    "reason": corrected_reason,
                }
            finally:
                await user_client.disconnect()
        finally:
            # Revert lockdown
            unlockdown_resp = await authenticated_client.set_lockdown(False)
            assert assert_success(unlockdown_resp) == {
                "status": False,
                "reason": None,
            }

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
            lockdown_resp = await authenticated_client.set_lockdown(
                True, "Emergency maintenance"
            )
            assert_success(lockdown_resp)

            event = await event_client.accept_event(timeout=5)
            assert event == {
                "event": "lockdown",
                "data": {"status": True, "reason": "Emergency maintenance"},
            }
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

            close_frame = excinfo.value.rcvd
            assert close_frame is not None
            assert close_frame.code == 1002
            assert close_frame.reason == (
                "Protocol error: invalid client-initiated stream"
            )

    @pytest.mark.asyncio
    async def test_audit_logs(self, authenticated_client: CFMSTestClient):
        # Do some actions to ensure audit logs exist
        await authenticated_client.create_directory(
            f"AuditLogFolder_{int(time.time())}"
        )

        # View audit logs
        logs_resp = await authenticated_client.view_audit_logs(page_size=10)
        logs_data = assert_success(logs_resp)

        assert "items" in logs_data
        assert isinstance(logs_data["items"], list)

        if len(logs_data["items"]) > 0:
            first_log = logs_data["items"][0]
            assert "action" in first_log
            assert "username" in first_log
            assert "logged_time" in first_log
