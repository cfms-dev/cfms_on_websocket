import tomlkit

from .support import _create_empty_database, _make_src_dir, _run_maintain


def test_options_cli_creates_updates_and_resets_group(tmp_path):
    src_dir = _make_src_dir(tmp_path)
    _create_empty_database(src_dir)
    payload_file = tmp_path / "server.json"
    payload_file.write_text('{"name":"Operator Server"}', encoding="utf-8")

    created = _run_maintain(
        tmp_path,
        [
            "config",
            "options",
            "set",
            "core",
            "server",
            payload_file.name,
            "--expected-revision",
            "0",
        ],
    )
    assert "Operator Server" in created.stdout
    inspected = _run_maintain(src_dir, ["config", "options", "get", "core", "server"])
    assert "Operator Server" in inspected.stdout
    conflict = _run_maintain(
        src_dir,
        [
            "config",
            "options",
            "set",
            "core",
            "server",
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
        ["config", "options", "reset", "core", "server", "--expected-revision", "1"],
    )
    assert "CFMS WebSocket Server" in reset.stdout


def test_migrate_options_cli_preview_then_apply_preserves_private_bootstrap(tmp_path):
    src_dir = _make_src_dir(tmp_path)
    _create_empty_database(src_dir)
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
    inspected = _run_maintain(src_dir, ["config", "options", "get", "core", "server"])
    assert "Imported Server" in inspected.stdout
