import sqlite3
from contextlib import closing

import pytest

from include.domains.identity.default_groups import DEFAULT_GROUP_PERMISSIONS


@pytest.mark.integration
def test_fresh_server_seeds_default_groups_with_original_time_defaults(
    server_process, test_server_settings
):
    with closing(
        sqlite3.connect(
            f"{(test_server_settings.src_dir / 'app.db').as_uri()}?mode=ro", uri=True
        )
    ) as connection:
        rows = connection.execute(
            "SELECT group_name, permission, granted, start_time, end_time "
            "FROM group_permissions WHERE group_name IN ('user', 'sysop')"
        ).fetchall()

    assert {(row[0], row[1]) for row in rows} == {
        (group, permission)
        for group, values in DEFAULT_GROUP_PERMISSIONS.items()
        for permission in values
    }
    assert len(rows) == sum(
        len(values) for values in DEFAULT_GROUP_PERMISSIONS.values()
    )
    assert all(
        granted == 1 and start > 0.0 and end is None
        for _, _, granted, start, end in rows
    )
