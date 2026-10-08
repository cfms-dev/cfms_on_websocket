import pytest

from .support import (
    _AUDIT_CUTOFF,
    _PERMISSION_NOW,
    _make_src_dir,
    _normalize_cli_output,
    _read_audit_ids,
    _read_jsonl,
    _read_permission_entries,
    _run_maintain,
    _run_python,
    _seed_audit_entries,
    _seed_permission_entries,
)

pytestmark = pytest.mark.integration


def test_permission_purge_dry_run_reports_eligible_entries_without_changes(tmp_path):
    src_dir = _make_src_dir(tmp_path)
    _seed_permission_entries(src_dir)

    dry_run = _run_maintain(
        src_dir,
        ["permission", "purge-expired", "--dry-run"],
        permission_now=_PERMISSION_NOW,
    )
    dry_run_output = _normalize_cli_output(dry_run.stdout)

    assert "User permission entries 1" in dry_run_output
    assert "Group permission entries 1" in dry_run_output
    assert "Cutoff timestamp 1408000.0" in dry_run_output
    assert _read_permission_entries(src_dir) == {
        "user": ["old_user", "recent_user", "cutoff_user", "permanent_user_revocation"],
        "group": [
            "old_group",
            "recent_group",
            "cutoff_group",
            "permanent_group_revocation",
        ],
    }


def test_permission_purge_aborted_confirmation_preserves_all_entries(tmp_path):
    src_dir = _make_src_dir(tmp_path)
    _seed_permission_entries(src_dir)

    aborted = _run_maintain(
        src_dir,
        ["permission", "purge-expired"],
        check=False,
        input_text="n\n",
        permission_now=_PERMISSION_NOW,
    )

    assert aborted.returncode == 1
    assert "Aborted." in aborted.stderr
    assert _read_permission_entries(src_dir) == {
        "user": ["old_user", "recent_user", "cutoff_user", "permanent_user_revocation"],
        "group": [
            "old_group",
            "recent_group",
            "cutoff_group",
            "permanent_group_revocation",
        ],
    }


def test_permission_purge_removes_expired_entries_and_preserves_revocations(tmp_path):
    src_dir = _make_src_dir(tmp_path)
    _seed_permission_entries(src_dir)

    purged = _run_maintain(
        src_dir,
        ["permission", "purge-expired", "--yes"],
        permission_now=_PERMISSION_NOW,
    )

    assert "Purged Permission Entries" in purged.stdout
    assert "Cutoff timestamp 1408000.0" in _normalize_cli_output(purged.stdout)
    assert _read_permission_entries(src_dir) == {
        "user": ["recent_user", "cutoff_user", "permanent_user_revocation"],
        "group": ["recent_group", "cutoff_group", "permanent_group_revocation"],
    }


def test_permission_purge_is_idempotent_after_removing_eligible_entries(tmp_path):
    src_dir = _make_src_dir(tmp_path)
    _seed_permission_entries(src_dir)
    _run_maintain(
        src_dir,
        ["permission", "purge-expired", "--yes"],
        permission_now=_PERMISSION_NOW,
    )
    remaining = _read_permission_entries(src_dir)

    repeated = _run_maintain(
        src_dir,
        ["permission", "purge-expired", "--yes"],
        permission_now=_PERMISSION_NOW,
    )

    assert "No expired permission entries are eligible" in repeated.stdout
    assert _read_permission_entries(src_dir) == remaining


def test_audit_export_applies_filters_and_serializes_matching_record(tmp_path):
    src_dir = _make_src_dir(tmp_path)
    _seed_audit_entries(src_dir)
    output_path = tmp_path / "important.jsonl"

    result = _run_maintain(
        tmp_path,
        [
            "audit",
            "export",
            output_path.name,
            "--before",
            _AUDIT_CUTOFF,
            "--action",
            "update_document",
            "--action",
            "login",
            "--result",
            "401",
            "--username",
            "alice",
            "--target",
            "alice",
            "--remote-address",
            "203.0.113.10",
        ],
    )
    rows = _read_jsonl(output_path)

    assert "Records" in result.stdout
    assert [row["id"] for row in rows] == ["old-login"]
    assert rows[0] == {
        "action": "login",
        "data": {"detail": {"message": "重要记录"}},
        "id": "old-login",
        "logged_time": 100.0,
        "remote_address": "203.0.113.10",
        "result": 401,
        "target": "alice",
        "username": "alice",
    }


def test_audit_export_orders_matching_records_by_logged_time(tmp_path):
    src_dir = _make_src_dir(tmp_path)
    _seed_audit_entries(src_dir)
    output_path = tmp_path / "ordered.jsonl"

    _run_maintain(
        tmp_path, ["audit", "export", output_path.name, "--before", _AUDIT_CUTOFF]
    )

    assert [row["id"] for row in _read_jsonl(output_path)] == [
        "old-login",
        "old-update",
    ]


def test_audit_export_refuses_to_replace_existing_output(tmp_path):
    src_dir = _make_src_dir(tmp_path)
    _seed_audit_entries(src_dir)
    output_path = tmp_path / "important.jsonl"
    output_path.write_bytes(b"existing archive\n")

    result = _run_maintain(
        tmp_path,
        ["audit", "export", output_path.name, "--before", _AUDIT_CUTOFF],
        check=False,
    )

    assert result.returncode == 1
    assert "already exists" in result.stdout + result.stderr
    assert output_path.read_bytes() == b"existing archive\n"


def test_audit_purge_dry_run_reports_counts_without_writing_archive_or_deleting(
    tmp_path,
):
    src_dir = _make_src_dir(tmp_path)
    _seed_audit_entries(src_dir, batch_size=1)
    archive_path = src_dir / "expired.jsonl"

    dry_run = _run_maintain(
        src_dir,
        ["audit", "purge", "--dry-run", "--before", _AUDIT_CUTOFF],
    )
    dry_run_output = _normalize_cli_output(dry_run.stdout)

    assert "Total 2" in dry_run_output
    assert "login 1" in dry_run_output
    assert "update_document 1" in dry_run_output
    assert "401 1" in dry_run_output
    assert not archive_path.exists()
    assert _read_audit_ids(src_dir) == [
        "old-login",
        "old-update",
        "cutoff",
        "new-entry",
    ]


def test_audit_purge_aborted_confirmation_does_not_archive_or_delete(tmp_path):
    src_dir = _make_src_dir(tmp_path)
    _seed_audit_entries(src_dir, batch_size=1)
    archive_path = src_dir / "expired.jsonl"

    aborted = _run_maintain(
        src_dir,
        [
            "audit",
            "purge",
            "--archive",
            str(archive_path),
            "--before",
            _AUDIT_CUTOFF,
        ],
        check=False,
        input_text="n\n",
    )

    assert aborted.returncode == 1
    assert "Aborted." in aborted.stderr
    assert not archive_path.exists()
    assert _read_audit_ids(src_dir) == [
        "old-login",
        "old-update",
        "cutoff",
        "new-entry",
    ]


def test_audit_purge_refuses_existing_archive_without_deleting_entries(tmp_path):
    src_dir = _make_src_dir(tmp_path)
    _seed_audit_entries(src_dir, batch_size=1)
    archive_path = src_dir / "expired.jsonl"
    archive_path.write_text("existing archive", encoding="utf-8")
    blocked = _run_maintain(
        src_dir,
        [
            "audit",
            "purge",
            "--archive",
            str(archive_path),
            "--before",
            _AUDIT_CUTOFF,
            "--yes",
        ],
        check=False,
    )

    assert blocked.returncode == 1
    assert "already exists" in blocked.stdout + blocked.stderr
    assert archive_path.read_text(encoding="utf-8") == "existing archive"
    assert _read_audit_ids(src_dir) == [
        "old-login",
        "old-update",
        "cutoff",
        "new-entry",
    ]


def test_audit_purge_archives_expired_entries_before_deleting_them(tmp_path):
    src_dir = _make_src_dir(tmp_path)
    _seed_audit_entries(src_dir, batch_size=1)
    archive_path = src_dir / "expired.jsonl"

    purged = _run_maintain(
        src_dir,
        [
            "audit",
            "purge",
            "--archive",
            str(archive_path),
            "--before",
            _AUDIT_CUTOFF,
            "--yes",
        ],
    )

    archived_rows = _read_jsonl(archive_path)
    assert [row["id"] for row in archived_rows] == [
        "old-login",
        "old-update",
    ]
    assert archived_rows[1]["username"] is None
    assert archived_rows[1]["data"] is None
    assert archived_rows[1]["remote_address"] is None
    assert "Archived" in purged.stdout
    assert "Deleted" in purged.stdout
    assert _read_audit_ids(src_dir) == ["cutoff", "new-entry"]


def test_audit_purge_is_idempotent_and_does_not_create_an_empty_archive(tmp_path):
    src_dir = _make_src_dir(tmp_path)
    _seed_audit_entries(src_dir, batch_size=1)
    archive_path = src_dir / "expired.jsonl"
    _run_maintain(
        src_dir,
        [
            "audit",
            "purge",
            "--archive",
            str(archive_path),
            "--before",
            _AUDIT_CUTOFF,
            "--yes",
        ],
    )

    repeated_archive = src_dir / "repeated.jsonl"
    repeated = _run_maintain(
        src_dir,
        [
            "audit",
            "purge",
            "--archive",
            str(repeated_archive),
            "--before",
            _AUDIT_CUTOFF,
            "--yes",
        ],
    )

    assert "No audit entries are eligible" in repeated.stdout
    assert not repeated_archive.exists()
    assert _read_audit_ids(src_dir) == ["cutoff", "new-entry"]


@pytest.mark.parametrize(
    ("args", "message"),
    [
        pytest.param(
            ["--before", _AUDIT_CUTOFF, "--yes"],
            "--archive is required",
            id="missing-archive",
        ),
        pytest.param(
            ["--dry-run", "--before", "2026-01-01T00:00:00"],
            "must include a timezone",
            id="naive-timestamp",
        ),
        pytest.param(
            ["--dry-run", "--before", "not-a-time"],
            "must be an ISO 8601 timestamp",
            id="invalid-timestamp",
        ),
    ],
)
def test_audit_purge_rejects_invalid_arguments(tmp_path, args, message):
    src_dir = _make_src_dir(tmp_path)

    result = _run_maintain(src_dir, ["audit", "purge", *args], check=False)

    assert result.returncode == 2
    assert message in _normalize_cli_output(result.stderr)


def test_audit_purge_partial_failure_keeps_complete_archive(tmp_path):
    src_dir = _make_src_dir(tmp_path)
    _seed_audit_entries(src_dir, batch_size=1)
    archive_path = src_dir / "partial.jsonl"
    _run_python(
        src_dir,
        '''
from maintenance.runtime import load_database_models

load_database_models()

from include.database.session import engine

with engine.begin() as connection:
    connection.exec_driver_sql(
        """CREATE TRIGGER reject_old_update
        BEFORE DELETE ON audit_entries
        WHEN OLD.id = 'old-update'
        BEGIN
            SELECT RAISE(ABORT, 'simulated audit deletion failure');
        END"""
    )
''',
    )

    result = _run_maintain(
        src_dir,
        [
            "audit",
            "purge",
            "--archive",
            str(archive_path),
            "--before",
            _AUDIT_CUTOFF,
            "--yes",
        ],
        check=False,
    )

    assert result.returncode == 1
    assert "after deleting 1 of 2 archived entries" in result.stdout + result.stderr
    assert [row["id"] for row in _read_jsonl(archive_path)] == [
        "old-login",
        "old-update",
    ]
    assert _read_audit_ids(src_dir) == ["old-update", "cutoff", "new-entry"]


def test_audit_purge_rejects_changed_candidate_count_before_deletion(tmp_path):
    src_dir = _make_src_dir(tmp_path)
    _seed_audit_entries(src_dir)
    archive_path = src_dir / "changed.jsonl"
    result = _run_python(
        src_dir,
        f"""
import datetime as dt

from maintenance.operations.audit import create_audit_selection, purge_audit_entries
from maintenance.operations.exceptions import MaintenanceOperationError

selection = create_audit_selection(
    before=dt.datetime.fromisoformat({_AUDIT_CUTOFF!r})
)
try:
    purge_audit_entries({str(archive_path)!r}, selection, expected_count=1)
except MaintenanceOperationError as exc:
    print(exc)
else:
    raise AssertionError("candidate-count change was not rejected")
""",
    )

    assert "Expected 1, archived 2" in result.stdout
    assert [row["id"] for row in _read_jsonl(archive_path)] == [
        "old-login",
        "old-update",
    ]
    assert _read_audit_ids(src_dir) == [
        "old-login",
        "old-update",
        "cutoff",
        "new-entry",
    ]
