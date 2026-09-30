from pathlib import Path
from types import SimpleNamespace

import pytest

from include.config.validation import ConfigValidationError


def test_startup_rejects_legacy_options_before_secrets_or_database_changes(monkeypatch):
    monkeypatch.chdir(Path(__file__).resolve().parents[2] / "src")
    import main as server_main

    def reject_legacy_options():
        raise ConfigValidationError("Run maintain config migrate-options")

    def unexpected_write(*_args, **_kwargs):
        pytest.fail("Startup must reject legacy options before modifying runtime files")

    monkeypatch.setattr(server_main, "prepare_logger", lambda: None)
    monkeypatch.setattr(
        server_main,
        "global_config",
        SimpleNamespace(
            require_migrated_options=reject_legacy_options,
            initialize_secrets=unexpected_write,
        ),
    )
    monkeypatch.setattr(server_main, "initialize_database_schema", unexpected_write)
    monkeypatch.setattr(server_main, "server_init", unexpected_write)

    with pytest.raises(ConfigValidationError, match="migrate-options"):
        server_main._run_server()


def test_old_database_is_rejected_before_secret_initialization_without_marker(
    monkeypatch, tmp_path
):
    monkeypatch.chdir(Path(__file__).resolve().parents[2] / "src")
    import main as server_main

    def reject_old_schema(*_args):
        raise RuntimeError("Run maintain database upgrade")

    def unexpected_write():
        pytest.fail("An outdated database must be rejected before changing secrets")

    monkeypatch.setattr(server_main, "EXECUTABLE_ABSPATH", tmp_path)
    monkeypatch.setattr(server_main, "prepare_logger", lambda: None)
    monkeypatch.setattr(
        server_main,
        "global_config",
        SimpleNamespace(
            require_migrated_options=lambda: None,
            initialize_secrets=unexpected_write,
        ),
    )
    monkeypatch.setattr(server_main, "initialize_database_schema", reject_old_schema)
    monkeypatch.setattr(server_main, "server_init", unexpected_write)

    with pytest.raises(RuntimeError, match="database upgrade"):
        server_main._run_server()
