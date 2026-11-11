from pathlib import Path

import pytest
import tomlkit

from include.config import paths
from maintenance.operations.config import (
    fill_pepper,
    inspect_config_template,
    sync_config_template,
)
from maintenance.operations.exceptions import MaintenanceOperationError

pytestmark = pytest.mark.component

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_SAMPLE_SOURCE = (_PROJECT_ROOT / "src" / "config.toml.sample").read_text(
    encoding="utf-8"
)


@pytest.fixture
def config_runtime(tmp_path, monkeypatch):
    def prepare_runtime(current, template=None) -> Path:
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "main.py").write_text("", encoding="utf-8")
        current_source = (
            tomlkit.dumps(current) if not isinstance(current, str) else current
        )
        template_value = template if template is not None else _SAMPLE_SOURCE
        template_source = (
            tomlkit.dumps(template_value)
            if not isinstance(template_value, str)
            else template_value
        )
        (src_dir / "config.toml").write_text(current_source, encoding="utf-8")
        (src_dir / "config.toml.sample").write_text(template_source, encoding="utf-8")
        monkeypatch.setattr(paths, "EXECUTABLE_ABSPATH", src_dir)
        monkeypatch.setattr(paths, "PROJECT_ABSPATH", src_dir.parent)
        monkeypatch.setattr(paths, "EXTENSION_ROOT", src_dir / "include" / "extensions")
        monkeypatch.chdir(src_dir)
        return src_dir

    return prepare_runtime


def _move_oidc_config_to_legacy_section(current, *, enabled):
    oidc = current["extensions"].pop("oidc_sso")
    oidc["enabled"] = enabled
    current["sso"] = {"oidc": oidc}


def test_config_inspection_reports_unknown_settings(config_runtime):
    current = tomlkit.parse(_SAMPLE_SOURCE)
    current["server"]["local_setting"] = "keep-me"
    config_runtime(current)

    inspection = inspect_config_template()

    assert inspection.unknown_paths == ("server.local_setting",)


def test_sync_preview_reports_missing_and_preserved_settings_without_writing(
    config_runtime,
):
    current = tomlkit.parse(_SAMPLE_SOURCE)
    del current["server"]["trusted_proxy_networks"]
    current["server"]["local_setting"] = "keep-me"
    src_dir = config_runtime(current)
    original_source = (src_dir / "config.toml").read_bytes()

    preview = sync_config_template(write=False)

    assert preview.changed is True
    assert preview.backup_path is None
    assert "server.trusted_proxy_networks" in preview.added_paths
    assert preview.preserved_paths == ("server.local_setting",)
    assert (src_dir / "config.toml").read_bytes() == original_source
    assert list(src_dir.glob("config.toml.backup-*")) == []


def test_sync_adds_template_settings_and_preserves_operator_values_and_comments(
    config_runtime,
):
    current = tomlkit.parse(_SAMPLE_SOURCE)
    del current["server"]["trusted_proxy_networks"]
    current["server"]["host"] = tomlkit.string("Operator Server")
    current["server"]["host"].comment("operator choice")
    current["server"]["local_setting"] = "keep-me"
    current["server"]["secret_key"] = "sensitive-value"
    src_dir = config_runtime(current)
    original_source = (src_dir / "config.toml").read_text(encoding="utf-8")

    result = sync_config_template()
    synchronized_source = (src_dir / "config.toml").read_text(encoding="utf-8")
    synchronized = tomlkit.parse(synchronized_source)

    assert result.backup_path is not None
    assert result.backup_path.read_text(encoding="utf-8") == original_source
    assert synchronized["server"]["host"] == "Operator Server"
    assert synchronized["server"]["local_setting"] == "keep-me"
    assert synchronized["server"]["secret_key"] == "sensitive-value"
    assert synchronized["server"]["trusted_proxy_networks"] == [
        "127.0.0.1/32",
        "::1/128",
    ]
    assert 'host = "Operator Server" # operator choice' in synchronized_source


def test_sync_is_idempotent_and_does_not_create_a_second_backup(config_runtime):
    current = tomlkit.parse(_SAMPLE_SOURCE)
    del current["server"]["trusted_proxy_networks"]
    src_dir = config_runtime(current)
    sync_config_template()
    synchronized_source = (src_dir / "config.toml").read_bytes()
    existing_backups = list(src_dir.glob("config.toml.backup-*"))

    repeated = sync_config_template()

    assert repeated.changed is False
    assert repeated.backup_path is None
    assert (src_dir / "config.toml").read_bytes() == synchronized_source
    assert list(src_dir.glob("config.toml.backup-*")) == existing_backups


def test_fill_pepper_keeps_original_config_when_atomic_replace_fails(
    monkeypatch,
    config_runtime,
):
    from maintenance.operations.config import sync as config_sync

    current = tomlkit.parse(_SAMPLE_SOURCE)
    current["security"]["pepper"] = ""
    src_dir = config_runtime(current)
    config_path = src_dir / "config.toml"
    original_source = config_path.read_bytes()

    def fail_replace(*_args) -> None:
        raise OSError("simulated atomic replace failure")

    monkeypatch.setattr(config_sync.os, "replace", fail_replace)

    with pytest.raises(MaintenanceOperationError, match="atomic replace failure"):
        fill_pepper()

    assert config_path.read_bytes() == original_source
    assert not any(src_dir.glob(".config.toml.*.tmp"))


def test_fill_pepper_rejects_non_table_security_section(
    config_runtime,
) -> None:
    config_runtime('security = "invalid"\n')

    with pytest.raises(MaintenanceOperationError, match="security must be a table"):
        fill_pepper()


def test_atomic_config_write_refuses_to_overwrite_same_timestamp_backup(
    monkeypatch,
    tmp_path,
):
    from maintenance.operations.config import sync as config_sync

    fixed_now = config_sync.dt.datetime(2026, 9, 13, tzinfo=config_sync.dt.UTC)

    class FixedDateTime:
        @classmethod
        def now(cls, timezone):
            assert timezone is config_sync.dt.UTC
            return fixed_now

    monkeypatch.setattr(config_sync.dt, "datetime", FixedDateTime)
    config_path = tmp_path / "config.toml"
    config_path.write_text("first\n", encoding="utf-8")
    first_source = config_sync.read_config_text(config_path)

    backup_path = config_sync.write_config_atomically(
        config_path,
        first_source,
        "second\n",
    )
    with pytest.raises(MaintenanceOperationError, match="backup already exists"):
        config_sync.write_config_atomically(
            config_path,
            "second\n",
            "third\n",
        )

    assert backup_path.read_bytes() == first_source.encode()
    assert config_path.read_bytes() == b"second\n"


@pytest.mark.parametrize("legacy_path", ["password", "creation", "oidc"])
def test_sync_preserves_legacy_business_values_for_explicit_migration(
    config_runtime, legacy_path
):
    current = tomlkit.parse(_SAMPLE_SOURCE)
    if legacy_path == "password":
        current["security"]["passwd_must_contain"] = [["A", "B"], "01"]
    elif legacy_path == "creation":
        current["document"] = {"upload": {"creation_rate_per_user": 50}}
    else:
        current["sso"] = {"oidc": {"auto_provision": True}}
    src_dir = config_runtime(current)
    original = (src_dir / "config.toml").read_bytes()
    with pytest.raises(MaintenanceOperationError):
        sync_config_template()
    assert (src_dir / "config.toml").read_bytes() == original


def test_sync_preserves_other_settings_beside_legacy_oidc(config_runtime):
    current = tomlkit.parse(_SAMPLE_SOURCE)
    _move_oidc_config_to_legacy_section(current, enabled=False)
    current["sso"]["saml"] = {"metadata_url": "https://idp.example/metadata"}
    src_dir = config_runtime(current)

    result = sync_config_template()
    synchronized = tomlkit.parse((src_dir / "config.toml").read_text(encoding="utf-8"))

    assert "oidc" not in synchronized["sso"]
    assert synchronized["sso"]["saml"]["metadata_url"] == (
        "https://idp.example/metadata"
    )
    assert result.preserved_paths == ("sso.saml",)


def test_sync_removes_selected_unknown_paths_and_preserves_other_unknowns(
    config_runtime,
):
    current = tomlkit.parse(_SAMPLE_SOURCE)
    current["server"]["old_setting"] = 1
    current["custom"] = {"enabled": True}
    src_dir = config_runtime(current)

    selected = sync_config_template(
        remove_paths=("server.old_setting",),
    )
    synchronized = tomlkit.parse((src_dir / "config.toml").read_text(encoding="utf-8"))

    assert selected.removed_paths == ("server.old_setting",)
    assert selected.preserved_paths == ("custom",)
    assert "old_setting" not in synchronized["server"]
    assert synchronized["custom"]["enabled"] is True


def test_sync_prunes_all_unknown_settings(config_runtime):
    current = tomlkit.parse(_SAMPLE_SOURCE)
    current["custom"] = {"enabled": True}
    src_dir = config_runtime(current)

    pruned = sync_config_template(prune=True)
    synchronized = tomlkit.parse((src_dir / "config.toml").read_text(encoding="utf-8"))

    assert pruned.removed_paths == ("custom",)
    assert "custom" not in synchronized


def test_sync_rejects_remove_path_that_is_not_unknown_without_writing(
    config_runtime,
):
    current = tomlkit.parse(_SAMPLE_SOURCE)
    src_dir = config_runtime(current)
    original_source = (src_dir / "config.toml").read_bytes()

    with pytest.raises(MaintenanceOperationError, match="Unknown --remove"):
        sync_config_template(remove_paths=("server.not_present",), write=False)

    assert (src_dir / "config.toml").read_bytes() == original_source
    assert list(src_dir.glob("config.toml.backup-*")) == []


def test_invalid_synchronized_config_does_not_write_or_back_up(config_runtime):
    current = tomlkit.parse(_SAMPLE_SOURCE)
    del current["server"]["file_chunk_size"]
    template = tomlkit.parse(_SAMPLE_SOURCE)
    template["server"]["file_chunk_size"] = 0
    src_dir = config_runtime(current, template)
    config_path = src_dir / "config.toml"
    original_source = config_path.read_text(encoding="utf-8")

    with pytest.raises(MaintenanceOperationError, match="positive integer"):
        sync_config_template()

    assert config_path.read_text(encoding="utf-8") == original_source
    assert list(src_dir.glob("config.toml.backup-*")) == []


@pytest.mark.parametrize(
    ("template_source", "message"),
    [
        (None, "template not found"),
        ("[server", "Unable to read configuration documents"),
    ],
)
def test_sync_rejects_missing_or_invalid_template(
    config_runtime, template_source, message
):
    current = tomlkit.parse(_SAMPLE_SOURCE)
    src_dir = config_runtime(current)
    template_path = src_dir / "config.toml.sample"
    if template_source is None:
        template_path.unlink()
    else:
        template_path.write_text(template_source, encoding="utf-8")

    with pytest.raises(MaintenanceOperationError, match=message):
        sync_config_template()


def test_sync_rejects_invalid_current_document_without_writing(config_runtime):
    src_dir = config_runtime("[server")
    config_path = src_dir / "config.toml"

    with pytest.raises(
        MaintenanceOperationError, match="Unable to read configuration documents"
    ):
        sync_config_template()

    assert config_path.read_text(encoding="utf-8") == "[server"
    assert list(src_dir.glob("config.toml.backup-*")) == []
