import time
import uuid

import pytest
from sqlalchemy import delete

from include.database.models.operations import AuditEntry
from include.database.session import Session
from tests.support.utils import assert_error, assert_success

pytestmark = pytest.mark.integration


@pytest.fixture
def audit_filter_entries(authenticated_client):
    prefix = f"extension.audit_test_{uuid.uuid4().hex}"
    keep, drop = f"{prefix}.keep", f"{prefix}.drop"
    timestamp = time.time()
    rows = [
        {
            "id": uuid.uuid4().hex,
            "action": action,
            "logged_time": timestamp + index // 2,
        }
        for index, action in enumerate([keep, drop, drop, keep, drop, keep, drop, drop])
    ]
    with Session.begin() as session:
        session.add_all(AuditEntry(**row, result=0) for row in rows)
    try:
        yield keep, drop, rows
    finally:
        with Session.begin() as session:
            session.execute(
                delete(AuditEntry).where(AuditEntry.id.in_([row["id"] for row in rows]))
            )


@pytest.mark.asyncio
async def test_exclusions_apply_before_pagination_and_bind_cursors(
    authenticated_client, audit_filter_entries
):
    keep, drop, rows = audit_filter_entries
    first = assert_success(
        await authenticated_client.view_audit_logs(
            page_size=2,
            filters=[drop, keep, keep],
            exclude_filters=[drop, "missing", drop],
        )
    )
    assert len(first["items"]) == 2
    assert first["has_more"] is True
    assert first["next_cursor"] is not None
    second = assert_success(
        await authenticated_client.view_audit_logs(
            page_size=2,
            cursor=first["next_cursor"],
            filters=[keep, drop],
            exclude_filters=["missing", drop],
        )
    )
    assert len(second["items"]) == 1
    assert second["has_more"] is False
    assert second["next_cursor"] is None
    actual_ids = [item["id"] for item in first["items"] + second["items"]]
    expected_ids = [
        row["id"]
        for row in sorted(
            rows, key=lambda row: (row["logged_time"], row["id"]), reverse=True
        )
        if row["action"] == keep
    ]
    assert actual_ids == expected_ids
    assert all(item["action"] == keep for item in first["items"] + second["items"])

    for includes, excludes in [
        ([keep, drop], []),
        ([keep], [drop]),
        ([keep, drop], [keep]),
    ]:
        assert_error(
            await authenticated_client.view_audit_logs(
                page_size=2,
                cursor=first["next_cursor"],
                filters=includes,
                exclude_filters=excludes,
            ),
            400,
        )


@pytest.mark.asyncio
async def test_empty_unknown_and_overlapping_exclusions(
    authenticated_client, audit_filter_entries
):
    keep, drop, rows = audit_filter_entries
    for excludes in [None, [], ["unknown_extension_action"]]:
        page = assert_success(
            await authenticated_client.view_audit_logs(
                filters=[keep, drop], exclude_filters=excludes
            )
        )
        assert {item["id"] for item in page["items"]} == {row["id"] for row in rows}
    empty = assert_success(
        await authenticated_client.view_audit_logs(
            filters=[keep], exclude_filters=[keep]
        )
    )
    assert empty["items"] == []
    assert empty["has_more"] is False
    assert empty["next_cursor"] is None

    for includes in [None, []]:
        defaults = assert_success(
            await authenticated_client.view_audit_logs(
                filters=includes,
                exclude_filters=["core.audit.entry.list", "core.setting.get"],
            )
        )
        assert defaults["items"]
        assert all(
            item["action"] not in {"core.audit.entry.list", "core.setting.get"}
            for item in defaults["items"]
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("invalid", [None, "core.setting.get", 1, [1], {}])
async def test_exclusions_reject_invalid_types(authenticated_client, invalid):
    response = await authenticated_client.send_request(
        "core.audit.entry.list", {"exclude_filters": invalid}
    )
    assert_error(response, 400)
    errors = response["data"]["errors"]
    assert errors
    assert all(error["loc"][0] == "exclude_filters" for error in errors)
    expected_type = "string_type" if isinstance(invalid, list) else "list_type"
    assert any(error["type"] == expected_type for error in errors)


@pytest.mark.asyncio
async def test_exclusions_do_not_bypass_audit_permission(low_privilege_client):
    assert_error(
        await low_privilege_client.view_audit_logs(
            exclude_filters=["core.audit.entry.list", "core.setting.get"]
        ),
        403,
    )


@pytest.mark.asyncio
async def test_client_defaults_hide_but_do_not_remove_recorded_actions(
    authenticated_client, audit_filter_entries
):
    keep, _drop, rows = audit_filter_entries
    hidden = [
        {"id": uuid.uuid4().hex, "action": action, "logged_time": time.time() + 10}
        for action in ["core.audit.entry.list", "core.setting.get"]
    ]
    rows.extend(hidden)
    with Session.begin() as session:
        session.add_all(AuditEntry(**row, result=0) for row in hidden)

    filtered = assert_success(
        await authenticated_client.view_audit_logs(
            exclude_filters=["core.audit.entry.list", "core.setting.get"]
        )
    )
    assert any(item["action"] == keep for item in filtered["items"])
    assert not {row["id"] for row in hidden} & {
        item["id"] for item in filtered["items"]
    }
    cleared = assert_success(
        await authenticated_client.view_audit_logs(filters=[], exclude_filters=[])
    )
    assert {row["id"] for row in hidden} <= {item["id"] for item in cleared["items"]}
