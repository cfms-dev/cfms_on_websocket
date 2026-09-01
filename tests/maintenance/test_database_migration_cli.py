from typer.testing import CliRunner

from maintenance.cli import app
from maintenance.operations.database import DatabaseMigrationResult


def test_database_migration_cli_reports_verified_result(monkeypatch, tmp_path) -> None:
    target_config = tmp_path / "target.toml"
    target_config.write_text("[database]\ntype='mysql'\n", encoding="utf-8")
    backup_path = tmp_path / "config.toml.backup"

    def migrate_database(path, *, activate, progress):
        assert path == target_config.resolve()
        assert activate is True
        assert progress is not None
        return DatabaseMigrationResult(
            source_dialect="sqlite",
            target_dialect="mysql",
            table_count=32,
            row_count=41,
            elapsed_seconds=1.25,
            target_config_path=target_config,
            config_backup_path=backup_path,
        )

    monkeypatch.setattr(
        "maintenance.cli.operations.migrate_database",
        migrate_database,
    )
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(
        app,
        [
            "database",
            "migrate",
            "--target-config",
            target_config.name,
            "--activate",
            "--yes",
        ],
    )

    assert result.exit_code == 0
    assert "sqlite" in result.stdout
    assert "mysql" in result.stdout
    assert "32" in result.stdout
    assert "41" in result.stdout
    assert "restart required" in result.stdout
