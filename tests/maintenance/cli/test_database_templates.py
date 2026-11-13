import pytest

from .support import (
    _PERMISSION_NOW,
    _make_src_dir,
    _read_permission_entries,
    _run_maintain,
)

pytestmark = pytest.mark.integration


def test_cli_write_changes_only_its_copy_of_the_database_template(
    tmp_path, permission_database_template
):
    first = _make_src_dir(
        tmp_path, "first", database_template=permission_database_template
    )
    second = _make_src_dir(
        tmp_path, "second", database_template=permission_database_template
    )
    original = _read_permission_entries(permission_database_template)

    result = _run_maintain(
        first, ["permission", "purge-expired", "--yes"], permission_now=_PERMISSION_NOW
    )

    assert result.returncode == 0
    assert _read_permission_entries(first) == {
        "user": ["recent_user", "cutoff_user", "permanent_user_revocation"],
        "group": ["recent_group", "cutoff_group", "permanent_group_revocation"],
    }
    assert _read_permission_entries(second) == original
    assert _read_permission_entries(permission_database_template) == original
