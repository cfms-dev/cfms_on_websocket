import pytest
import tomlkit

from .support import _make_src_dir, _run_maintain

pytestmark = pytest.mark.integration


def test_options_cli_creates_updates_and_resets_setting(
    empty_database_template, tmp_path
):
    src_dir = _make_src_dir(tmp_path, database_template=empty_database_template)
    payload_file = tmp_path / "server.json"
    payload_file.write_text('"Operator Server"', encoding="utf-8")

    created = _run_maintain(
        tmp_path,
        [
            "config",
            "options",
            "set",
            "server",
            "name",
            payload_file.name,
            "--expected-revision",
            "0",
        ],
    )
    assert "Operator Server" in created.stdout
    inspected = _run_maintain(src_dir, ["config", "options", "get", "server", "name"])
    assert "Operator Server" in inspected.stdout
    conflict = _run_maintain(
        src_dir,
        [
            "config",
            "options",
            "set",
            "server",
            "name",
            str(payload_file),
            "--expected-revision",
            "0",
        ],
        check=False,
    )
    assert conflict.returncode == 1
    assert "revision conflict" in conflict.stdout + conflict.stderr
    reset = _run_maintain(
        src_dir,
        [
            "config",
            "options",
            "reset",
            "server",
            "name",
            "--expected-revision",
            "1",
        ],
    )
    assert "CFMS WebSocket Server" in reset.stdout


def test_options_cli_set_many_validates_entry_revisions(
    empty_database_template, tmp_path
):
    src_dir = _make_src_dir(tmp_path, database_template=empty_database_template)
    payload_file = tmp_path / "updates.json"
    payload_file.write_text(
        '{"name":{"value":"Batch Server","expected_revision":0}}',
        encoding="utf-8",
    )

    created = _run_maintain(
        src_dir,
        ["config", "options", "set-many", "server", str(payload_file)],
    )
    assert "Batch Server" in created.stdout
    stale = _run_maintain(
        src_dir,
        ["config", "options", "set-many", "server", str(payload_file)],
        check=False,
    )
    assert stale.returncode == 1
    assert "revision conflict" in stale.stdout + stale.stderr
    inspected = _run_maintain(src_dir, ["config", "options", "get", "server", "name"])
    assert "Batch Server" in inspected.stdout


def test_options_cli_set_many_rejects_unknown_entry_fields(
    empty_database_template, tmp_path
):
    src_dir = _make_src_dir(tmp_path, database_template=empty_database_template)
    payload_file = tmp_path / "invalid-updates.json"
    payload_file.write_text(
        '{"name":{"value":"Rejected Server","expected_revision":0,"extra":true}}',
        encoding="utf-8",
    )

    rejected = _run_maintain(
        src_dir,
        ["config", "options", "set-many", "server", str(payload_file)],
        check=False,
    )
    assert rejected.returncode == 1
    assert "extra" in rejected.stdout + rejected.stderr
    inspected = _run_maintain(src_dir, ["config", "options", "get", "server", "name"])
    assert "CFMS WebSocket Server" in inspected.stdout
    assert "Rejected Server" not in inspected.stdout


def test_migrate_options_cli_preview_then_apply_preserves_private_bootstrap(
    empty_database_template, tmp_path
):
    src_dir = _make_src_dir(tmp_path, database_template=empty_database_template)
    config_path = src_dir / "config.toml"
    document = tomlkit.parse(config_path.read_text(encoding="utf-8"))
    document["server"]["name"] = "Imported Server"
    document["server"]["secret_key"] = "must-not-be-printed"
    config_path.write_text(tomlkit.dumps(document), encoding="utf-8")
    original = config_path.read_bytes()

    preview = _run_maintain(
        src_dir, ["config", "migrate-options", "--check"], check=False
    )

    assert preview.returncode == 1
    assert config_path.read_bytes() == original
    assert "must-not-be-printed" not in preview.stdout + preview.stderr
    applied = _run_maintain(src_dir, ["config", "migrate-options", "--yes"])
    assert "must-not-be-printed" not in applied.stdout + applied.stderr
    migrated = tomlkit.parse(config_path.read_text(encoding="utf-8"))
    assert "name" not in migrated["server"]
    assert migrated["server"]["secret_key"] == "must-not-be-printed"
    assert len(list(src_dir.glob("config.toml.backup-*"))) == 1
    inspected = _run_maintain(src_dir, ["config", "options", "get", "server", "name"])
    assert "Imported Server" in inspected.stdout
