import time

import pytest

from tests.test_client import CFMSTestClient
from tests.utils import assert_error, assert_success


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
