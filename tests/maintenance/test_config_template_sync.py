from pathlib import Path

import pytest
import tomlkit

from maintenance.operations.config import (
    inspect_config_template,
    sync_config_template,
)
from maintenance.operations.exceptions import MaintenanceOperationError

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_SAMPLE_SOURCE = (_PROJECT_ROOT / "src" / "config.toml.sample").read_text(
    encoding="utf-8"
)


def _prepare_src(tmp_path: Path, current, template=None) -> Path:
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "main.py").write_text("", encoding="utf-8")
    current_source = tomlkit.dumps(current) if not isinstance(current, str) else current
    template_value = template if template is not None else _SAMPLE_SOURCE
    template_source = (
        tomlkit.dumps(template_value)
        if not isinstance(template_value, str)
        else template_value
    )
    (src_dir / "config.toml").write_text(current_source, encoding="utf-8")
    (src_dir / "config.toml.sample").write_text(template_source, encoding="utf-8")
    return src_dir


def test_sync_adds_template_settings_preserves_values_and_is_idempotent(
    monkeypatch, tmp_path
):
    current = tomlkit.parse(_SAMPLE_SOURCE)
    del current["server"]["trusted_proxy_networks"]
    current["server"]["name"] = tomlkit.string("Operator Server")
    current["server"]["name"].comment("operator choice")
    current["server"]["local_setting"] = "keep-me"
    current["server"]["secret_key"] = "sensitive-value"
    src_dir = _prepare_src(tmp_path, current)
    original_source = (src_dir / "config.toml").read_text(encoding="utf-8")
    monkeypatch.chdir(src_dir)

    inspection = inspect_config_template()
    preview = sync_config_template(write=False)

    assert inspection.unknown_paths == ("server.local_setting",)
    assert preview.changed is True
    assert preview.backup_path is None
    assert "server.trusted_proxy_networks" in preview.added_paths
    assert preview.preserved_paths == ("server.local_setting",)

    result = sync_config_template()
    synchronized_source = (src_dir / "config.toml").read_text(encoding="utf-8")
    synchronized = tomlkit.parse(synchronized_source)

    assert result.backup_path is not None
    assert result.backup_path.read_text(encoding="utf-8") == original_source
    assert synchronized["server"]["name"] == "Operator Server"
    assert synchronized["server"]["local_setting"] == "keep-me"
    assert synchronized["server"]["secret_key"] == "sensitive-value"
    assert synchronized["server"]["trusted_proxy_networks"] == [
        "127.0.0.1/32",
        "::1/128",
    ]
    assert 'name = "Operator Server" # operator choice' in synchronized_source
    assert sync_config_template(write=False).changed is False


def test_sync_applies_all_known_legacy_migrations(monkeypatch, tmp_path):
    current = tomlkit.parse(_SAMPLE_SOURCE)
    current["database"]["db_name"] = "legacy_database"
    del current["database"]["name"]
    current["sso"]["oidc"]["enabled"] = True
    current["extensions"]["enabled"] = []
    current["document"]["allow_name_duplicate"] = True
    upload = current["document"]["upload"]
    del upload["creation_risk_control"]
    upload["creation_rate_window_seconds"] = 300
    upload["creation_rate_per_user"] = 50
    upload["creation_rate_per_ip"] = 125
    current["security"]["passwd_must_contain"] = [["A", "B"], "01"]
    del current["security"]["passwd_rules"]
    del current["security"]["passwd_min_passed_count"]
    src_dir = _prepare_src(tmp_path, current)
    monkeypatch.chdir(src_dir)

    result = sync_config_template()
    synchronized = tomlkit.parse((src_dir / "config.toml").read_text(encoding="utf-8"))

    assert len(result.migrations) == 4
    assert "document.allow_name_duplicate" in result.removed_paths
    assert synchronized["database"]["name"] == "legacy_database"
    assert "db_name" not in synchronized["database"]
    assert synchronized["extensions"]["enabled"] == ["oidc_sso"]
    assert "enabled" not in synchronized["sso"]["oidc"]
    risk_control = synchronized["document"]["upload"]["creation_risk_control"]
    assert risk_control["refill_period_seconds"] == 300
    assert risk_control["account_refill_tokens"] == 50
    assert risk_control["account_capacity"] == 10
    assert risk_control["ip_refill_tokens"] == 125
    assert risk_control["ip_capacity"] == 25
    assert synchronized["security"]["passwd_rules"] == ["(?:A|B)", "(?:0|1)"]
    assert synchronized["security"]["passwd_min_passed_count"] == 2
    assert "passwd_must_contain" not in synchronized["security"]
    assert "allow_name_duplicate" not in synchronized["document"]


def test_sync_keeps_new_targets_and_warns_for_unconvertible_values(
    monkeypatch, tmp_path
):
    current = tomlkit.parse(_SAMPLE_SOURCE)
    current["database"]["db_name"] = "legacy_database"
    current["database"]["name"] = "current_database"
    current["sso"]["oidc"]["enabled"] = "true"
    current["security"]["passwd_must_contain"] = [["AB"]]
    current["document"]["upload"]["creation_rate_per_user"] = 0
    src_dir = _prepare_src(tmp_path, current)
    monkeypatch.chdir(src_dir)

    result = sync_config_template()
    synchronized = tomlkit.parse((src_dir / "config.toml").read_text(encoding="utf-8"))

    assert synchronized["database"]["name"] == "current_database"
    assert synchronized["extensions"]["enabled"] == []
    assert (
        synchronized["security"]["passwd_rules"] == current["security"]["passwd_rules"]
    )
    assert (
        synchronized["document"]["upload"]["creation_risk_control"][
            "account_refill_tokens"
        ]
        == current["document"]["upload"]["creation_risk_control"][
            "account_refill_tokens"
        ]
    )
    assert len(result.warnings) == 3


def test_sync_removes_selected_unknown_paths_and_can_prune(monkeypatch, tmp_path):
    current = tomlkit.parse(_SAMPLE_SOURCE)
    current["server"]["old_setting"] = 1
    current["custom"] = {"enabled": True}
    src_dir = _prepare_src(tmp_path, current)
    monkeypatch.chdir(src_dir)

    selected = sync_config_template(
        remove_paths=("server.old_setting",),
    )
    synchronized = tomlkit.parse((src_dir / "config.toml").read_text(encoding="utf-8"))

    assert selected.removed_paths == ("server.old_setting",)
    assert selected.preserved_paths == ("custom",)
    assert "old_setting" not in synchronized["server"]
    assert synchronized["custom"]["enabled"] is True

    pruned = sync_config_template(prune=True)
    synchronized = tomlkit.parse((src_dir / "config.toml").read_text(encoding="utf-8"))

    assert pruned.removed_paths == ("custom",)
    assert "custom" not in synchronized
    with pytest.raises(MaintenanceOperationError, match="Unknown --remove"):
        sync_config_template(remove_paths=("server.not_present",), write=False)


def test_invalid_synchronized_config_does_not_write_or_back_up(monkeypatch, tmp_path):
    current = tomlkit.parse(_SAMPLE_SOURCE)
    del current["server"]["file_chunk_size"]
    template = tomlkit.parse(_SAMPLE_SOURCE)
    template["server"]["file_chunk_size"] = 0
    src_dir = _prepare_src(tmp_path, current, template)
    config_path = src_dir / "config.toml"
    original_source = config_path.read_text(encoding="utf-8")
    monkeypatch.chdir(src_dir)

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
    monkeypatch, tmp_path, template_source, message
):
    current = tomlkit.parse(_SAMPLE_SOURCE)
    src_dir = _prepare_src(tmp_path, current)
    template_path = src_dir / "config.toml.sample"
    if template_source is None:
        template_path.unlink()
    else:
        template_path.write_text(template_source, encoding="utf-8")
    monkeypatch.chdir(src_dir)

    with pytest.raises(MaintenanceOperationError, match=message):
        sync_config_template()


def test_sync_rejects_invalid_current_document_without_writing(monkeypatch, tmp_path):
    src_dir = _prepare_src(tmp_path, "[server")
    config_path = src_dir / "config.toml"
    monkeypatch.chdir(src_dir)

    with pytest.raises(
        MaintenanceOperationError, match="Unable to read configuration documents"
    ):
        sync_config_template()

    assert config_path.read_text(encoding="utf-8") == "[server"
    assert list(src_dir.glob("config.toml.backup-*")) == []
