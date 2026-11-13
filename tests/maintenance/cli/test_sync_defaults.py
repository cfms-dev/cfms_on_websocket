import sqlite3
from contextlib import closing

import pytest

from include.domains.identity.default_groups import DEFAULT_GROUP_PERMISSIONS
from include.runtime_lock import server_runtime_lock

from .support import _make_src_dir, _run_maintain

pytestmark = pytest.mark.integration


@pytest.fixture
def default_group_root(empty_database_template, tmp_path):
    root = _make_src_dir(tmp_path, database_template=empty_database_template)
    with closing(sqlite3.connect(root / "app.db")) as connection, connection:
        connection.executemany(
            "INSERT INTO user_groups (group_name) VALUES (?)", [("user",), ("sysop",)]
        )
    return root


@pytest.mark.parametrize(
    ("options", "input_text", "exit_code", "applied"),
    [
        pytest.param(["--dry-run"], None, 0, False, id="preview"),
        pytest.param(["--dry-run", "--yes"], None, 0, False, id="preview-with-yes"),
        pytest.param([], "n\n", 1, False, id="cancel"),
        pytest.param([], "y\n", 0, True, id="confirm"),
        pytest.param(["--yes"], None, 0, True, id="yes"),
    ],
)
def test_sync_defaults_cli_confirmation_and_preview(
    default_group_root, options, input_text, exit_code, applied
):
    result = _run_maintain(
        default_group_root,
        ["permission", "sync-defaults", *options],
        input_text=input_text,
        check=False,
    )

    assert result.returncode == exit_code, result.stdout + result.stderr
    with closing(sqlite3.connect(default_group_root / "app.db")) as connection:
        rows = connection.execute(
            "SELECT group_name, permission, granted, start_time, end_time "
            "FROM group_permissions ORDER BY group_name, permission"
        ).fetchall()
        expected = (
            {
                (group, permission, 1, 0.0, None)
                for group, values in DEFAULT_GROUP_PERMISSIONS.items()
                for permission in values
            }
            if applied
            else set()
        )
        assert set(rows) == expected
        assert len(rows) == len(expected)


@pytest.mark.parametrize(
    ("selection", "expected_groups"),
    [
        (["--group", "user"], {"user"}),
        (["--group", "sysop"], {"sysop"}),
        (["--group", "user", "--group", "user"], {"user"}),
        (["--group", "sysop", "--group", "user"], {"sysop", "user"}),
    ],
)
def test_sync_defaults_cli_selection_and_idempotence(
    default_group_root, selection, expected_groups
):
    arguments = ["permission", "sync-defaults", *selection, "--yes"]
    first = _run_maintain(default_group_root, arguments)
    repeated = _run_maintain(default_group_root, arguments[:-1], input_text="n\n")

    assert first.returncode == repeated.returncode == 0
    with closing(sqlite3.connect(default_group_root / "app.db")) as connection:
        rows = connection.execute("SELECT group_name FROM group_permissions").fetchall()
        assert len(rows) == sum(
            len(DEFAULT_GROUP_PERMISSIONS[group]) for group in expected_groups
        )
        assert {group for (group,) in rows} == expected_groups


@pytest.mark.parametrize("remaining", [(), ("user",)])
def test_sync_defaults_cli_skips_missing_groups(default_group_root, remaining):
    with (
        closing(sqlite3.connect(default_group_root / "app.db")) as connection,
        connection,
    ):
        connection.execute("DELETE FROM user_groups")
        connection.executemany(
            "INSERT INTO user_groups (group_name) VALUES (?)",
            [(name,) for name in remaining],
        )

    result = _run_maintain(default_group_root, ["permission", "sync-defaults", "--yes"])

    assert result.returncode == 0
    with closing(sqlite3.connect(default_group_root / "app.db")) as connection:
        assert connection.execute(
            "SELECT group_name FROM user_groups ORDER BY group_name"
        ).fetchall() == [(name,) for name in remaining]
        assert connection.execute(
            "SELECT COUNT(*) FROM group_permissions"
        ).fetchone() == (
            sum(len(DEFAULT_GROUP_PERMISSIONS[group]) for group in remaining),
        )


def test_sync_defaults_cli_rejects_unknown_group_before_loading_database(tmp_path):
    result = _run_maintain(
        tmp_path,
        ["permission", "sync-defaults", "--group", "staff", "--yes"],
        check=False,
    )

    assert result.returncode == 2, result.stdout + result.stderr
    assert not list(tmp_path.rglob("app.db"))


def test_sync_defaults_cli_online_preview_and_offline_write(default_group_root):
    with server_runtime_lock(default_group_root):
        preview = _run_maintain(
            default_group_root, ["permission", "sync-defaults", "--dry-run"]
        )
        blocked = _run_maintain(
            default_group_root,
            ["permission", "sync-defaults", "--yes"],
            check=False,
        )

    assert preview.returncode == 0
    assert blocked.returncode == 1, blocked.stdout + blocked.stderr
    with closing(sqlite3.connect(default_group_root / "app.db")) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM group_permissions"
        ).fetchone() == (0,)
    assert (
        _run_maintain(
            default_group_root, ["permission", "sync-defaults", "--yes"]
        ).returncode
        == 0
    )


def test_sync_defaults_cli_reports_database_failure(default_group_root):
    with (
        closing(sqlite3.connect(default_group_root / "app.db")) as connection,
        connection,
    ):
        connection.execute("DROP TABLE group_permissions")

    result = _run_maintain(
        default_group_root,
        ["permission", "sync-defaults", "--dry-run"],
        check=False,
    )

    assert result.returncode == 1, result.stdout + result.stderr
