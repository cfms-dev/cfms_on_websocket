import shutil
import zipfile
from pathlib import Path

import tomlkit

from .support import (
    _SRC_PATH,
    _create_empty_database,
    _make_src_dir,
    _normalize_cli_output,
    _run_maintain,
)


def test_backup_import_abort_uses_typer_abort_before_operation(tmp_path):
    src_dir = _make_src_dir(tmp_path)

    result = _run_maintain(
        src_dir,
        ["backup", "import", "missing.confbak", "--key", "abc"],
        check=False,
        input_text="n\n",
    )

    assert result.returncode == 1
    assert "Aborted." in result.stderr
    assert not (src_dir / "init").exists()


def test_extension_cli_lists_installs_and_enables(tmp_path):
    src_dir = _make_src_dir(tmp_path)
    shutil.copytree(
        _SRC_PATH / "include" / "extensions",
        src_dir / "include" / "extensions",
    )
    package = tmp_path / "cli_extension.zip"
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr(
            "manifest.toml",
            """manifest_version = 2

[extension]
identifier = "cli_extension"
name = "CLI Extension"
version = "1.0.0"
authors = ["Test Author"]
license = "Apache-2.0"
""",
        )
        archive.writestr("_extension.py", "raise RuntimeError('must not import')\n")

    listed = _run_maintain(tmp_path, ["extension", "list"])
    aborted = _run_maintain(
        tmp_path,
        ["extension", "install", package.name],
        check=False,
        input_text="n\n",
    )
    assert aborted.returncode == 1
    assert "Aborted" in aborted.stderr
    assert not (src_dir / "include" / "extensions" / "cli_extension").exists()

    installed = _run_maintain(
        tmp_path,
        ["extension", "install", package.name, "--yes"],
    )
    enabled = _run_maintain(
        tmp_path,
        ["extension", "enable", "cli_extension", "--yes"],
    )
    info = _run_maintain(tmp_path, ["extension", "info", "cli_extension"])

    assert "builtin" in listed.stdout
    assert "remains disabled" in _normalize_cli_output(installed.stdout)
    assert "Restart any running server" in _normalize_cli_output(enabled.stdout)
    assert "CLI Extension" in _normalize_cli_output(info.stdout)
    config = tomlkit.parse((src_dir / "config.toml").read_text(encoding="utf-8"))
    assert config["extensions"]["enabled"] == ["cli_extension"]


def test_backup_export_interactive_rejects_other_arguments(tmp_path):
    src_dir = _make_src_dir(tmp_path)
    cases = [
        ["backup", "export", "-i", "backup.confbak"],
        ["backup", "export", "-i", "--key-out", "backup.key"],
        ["backup", "export", "-i", "--verbose"],
    ]

    for args in cases:
        result = _run_maintain(src_dir, args, check=False)
        output = _normalize_cli_output(result.stdout + result.stderr)

        assert result.returncode != 0
        assert "Interactive export must be invoked" in output


def test_backup_export_interactive_wizard_and_import(tmp_path):
    source_src = _make_src_dir(tmp_path, "interactive-source")
    target_src = _make_src_dir(tmp_path, "interactive-target")
    _create_empty_database(source_src)

    input_text = "\n\n\n\n\ninteractive.confbak\nfile\ninteractive.key\ny\n"
    export_result = _run_maintain(
        source_src,
        ["backup", "export", "-i"],
        input_text=input_text,
    )

    assert "Backup Wizard" in export_result.stdout
    assert "Backup Export Summary" in export_result.stdout
    assert (source_src / "interactive.confbak").is_file()
    assert (source_src / "interactive.key").is_file()
    key_text = (source_src / "interactive.key").read_text(encoding="utf-8").strip()
    key_data = key_text.replace("-", "")
    assert len(key_data) == 52
    assert not set(key_data) & set("01OILl")

    import_result = _run_maintain(
        target_src,
        [
            "backup",
            "import",
            str(source_src / "interactive.confbak"),
            "--key-file",
            str(source_src / "interactive.key"),
            "--yes",
        ],
    )

    assert "Backup Import" in import_result.stdout
    assert (target_src / "init").is_file()


def test_backup_export_info_and_import(tmp_path):
    source_src = _make_src_dir(tmp_path, "source-src")
    target_src = _make_src_dir(tmp_path, "target-src")
    source_workdir = source_src / "operator"
    target_workdir = target_src / "operator"
    source_workdir.mkdir()
    target_workdir.mkdir()
    _create_empty_database(source_src)

    export_result = _run_maintain(
        source_workdir,
        [
            "backup",
            "export",
            "backup.confbak",
            "--key-out",
            "backup.key",
            "--verbose",
        ],
    )

    assert "Backup Export" in export_result.stdout
    assert "Backup export completed" in export_result.stderr
    assert "Starting backup export" in export_result.stderr
    assert "Adding archive member" in export_result.stderr
    assert (source_workdir / "backup.confbak").is_file()
    assert (source_workdir / "backup.key").is_file()
    assert not (source_src / "backup.confbak").exists()

    info_result = _run_maintain(
        source_workdir,
        ["backup", "info", "backup.confbak", "--verbose"],
    )

    assert "CFMS Backup" in info_result.stdout
    assert "AES-256-GCM" in info_result.stdout
    assert "Reading backup info" in info_result.stderr

    import_result = _run_maintain(
        target_workdir,
        [
            "backup",
            "import",
            str(Path("..", "..", "source-src", "operator", "backup.confbak")),
            "--key-file",
            str(Path("..", "..", "source-src", "operator", "backup.key")),
            "--yes",
            "--verbose",
        ],
    )

    assert "Backup Import" in import_result.stdout
    assert "Backup import completed" in import_result.stderr
    assert "Starting backup import" in import_result.stderr
    assert (target_src / "init").is_file()
