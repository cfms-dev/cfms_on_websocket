import os
import subprocess
import sys
from pathlib import Path
from shutil import copyfile

import pytest
from tomlkit import parse

from include.config import paths
from tests.support.config import (
    PROJECT_ROOT,
    SOURCE_ROOT,
    isolated_test_runtime,
    managed_test_config,
    write_test_config,
)

pytestmark = pytest.mark.component


@pytest.mark.parametrize("fail_import", [False, True])
def test_runtime_is_ready_before_initial_conftest_import_and_cleaned_up(
    tmp_path, fail_import
):
    copyfile(PROJECT_ROOT / "tests/conftest.py", tmp_path / "conftest.py")
    nested = tmp_path / "nested"
    nested.mkdir()
    runtime_record = tmp_path / "runtime.txt"
    conftest = (
        "from pathlib import Path\n"
        "from include.config import paths\n"
        "from tests.support.config import SOURCE_ROOT\n"
        "assert paths.EXECUTABLE_ABSPATH != SOURCE_ROOT\n"
        "from include.database.models import User\n"
        f"Path({str(runtime_record)!r}).write_text("
        "str(paths.EXECUTABLE_ABSPATH), encoding='utf-8')\n"
    )
    if fail_import:
        conftest += "raise RuntimeError('initial conftest failure')\n"
    (nested / "conftest.py").write_text(conftest, encoding="utf-8")
    (nested / "test_probe.py").write_text(
        "import pytest\n"
        "@pytest.mark.component\n"
        "def test_probe(protected_test_config):\n"
        "    assert protected_test_config.config_path.is_file()\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-c",
            str(PROJECT_ROOT / "pytest.ini"),
            str(nested),
            "-q",
        ],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    output = result.stdout + result.stderr
    assert result.returncode == (4 if fail_import else 0), output
    if fail_import:
        assert "initial conftest failure" in output
    else:
        assert "1 passed" in output
    assert runtime_record.is_file(), output
    runtime = Path(runtime_record.read_text(encoding="utf-8"))
    assert runtime != SOURCE_ROOT
    assert not runtime.parent.exists()


def _copy_config_sample(src_dir):
    src_dir.mkdir()
    copyfile(SOURCE_ROOT / "config.toml.sample", src_dir / "config.toml.sample")


def test_managed_test_config_removes_generated_config_and_restores_environment(
    tmp_path, monkeypatch
):
    src_dir = tmp_path / "src"
    _copy_config_sample(src_dir)
    monkeypatch.setenv("CFMS_TEST_HOST", "original-host")
    monkeypatch.delenv("CFMS_TEST_PORT", raising=False)
    monkeypatch.delenv("CFMS_TEST_USE_SSL", raising=False)

    with managed_test_config(src_dir) as settings:
        config = parse(settings.config_path.read_text(encoding="utf-8"))

        assert settings.src_dir == src_dir
        assert config["server"]["host"] == "::1"
        assert config["server"]["port"] == settings.port
        assert os.environ["CFMS_TEST_HOST"] == "::1"
        assert os.environ["CFMS_TEST_PORT"] == str(settings.port)
        assert os.environ["CFMS_TEST_USE_SSL"] == "1"

    assert not (src_dir / "config.toml").exists()
    assert os.environ["CFMS_TEST_HOST"] == "original-host"
    assert "CFMS_TEST_PORT" not in os.environ
    assert "CFMS_TEST_USE_SSL" not in os.environ


def test_write_test_config_can_disable_debug_for_load_tests(tmp_path):
    src_dir = tmp_path / "src"
    _copy_config_sample(src_dir)

    settings = write_test_config(src_dir, 5104, debug=False)

    config = parse(settings.config_path.read_text(encoding="utf-8"))
    assert config["debug"] is False


def test_managed_test_config_restores_existing_config_exactly(tmp_path):
    src_dir = tmp_path / "src"
    _copy_config_sample(src_dir)
    config_path = src_dir / "config.toml"
    original = b'[operator]\nvalue = "preserve exactly"\n'
    config_path.write_bytes(original)

    with managed_test_config(src_dir):
        config_path.write_bytes(b"changed")

    assert config_path.read_bytes() == original


def test_managed_test_config_restores_existing_config_after_body_failure(tmp_path):
    src_dir = tmp_path / "src"
    _copy_config_sample(src_dir)
    config_path = src_dir / "config.toml"
    original = b'[operator]\nvalue = "preserve exactly"\n'
    config_path.write_bytes(original)

    with (  # noqa: PT012 -- exception propagation through the context is the contract
        pytest.raises(RuntimeError, match="test failure"),
        managed_test_config(src_dir),
    ):
        config_path.write_bytes(b"changed")
        raise RuntimeError("test failure")

    assert config_path.read_bytes() == original


def test_session_runtime_paths_are_isolated_from_development_files(
    protected_test_config,
):
    src_dir = protected_test_config.src_dir

    assert src_dir != SOURCE_ROOT
    assert not src_dir.is_relative_to(SOURCE_ROOT.parent)
    assert paths.EXECUTABLE_ABSPATH == src_dir
    assert paths.PROJECT_ABSPATH == src_dir.parent
    assert paths.EXTENSION_ROOT == src_dir / "include" / "extensions"


def test_isolated_runtime_copies_resources_without_development_state(tmp_path):
    source = tmp_path / "development"
    _copy_config_sample(source)
    for directory in ("include", "maintenance", "alembic", "content/ssl/client"):
        (source / directory).mkdir(parents=True)
    resources = {
        "main.py": b"# server entrypoint\n",
        "alembic.ini": b"[alembic]\n",
        "include/__init__.py": b"# current source\n",
        "content/hello": b"hello",
        "content/ssl/client/ca.pem": b"trusted certificate",
    }
    development_state = {
        "config.toml": b"operator configuration",
        "app.db": b"operator database",
        "app.db-wal": b"operator WAL",
        "app.db-shm": b"operator shared memory",
        "init": b"initialized",
        "admin_password.txt": b"operator credential",
        "content/files/document": b"operator file",
        "content/logs/server.log": b"operator log",
        "content/ssl/server.key": b"operator private key",
        "include/__pycache__/module.pyc": b"cache",
    }
    for relative, content in (resources | development_state).items():
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    with isolated_test_runtime(source) as settings:
        runtime = settings.src_dir
        for relative, expected in resources.items():
            assert (runtime / relative).read_bytes() == expected
        assert settings.config_path.read_bytes() != development_state["config.toml"]
        for relative in development_state.keys() - {"config.toml"}:
            assert not (runtime / relative).exists(), relative

    assert not runtime.exists()
    for relative, expected in development_state.items():
        assert (source / relative).read_bytes() == expected


def test_isolated_runtime_removes_temporary_tree_after_body_failure(monkeypatch):
    monkeypatch.setenv("CFMS_TEST_HOST", "original-host")

    with (  # noqa: PT012 -- exception propagation must exercise temporary-tree cleanup
        pytest.raises(RuntimeError, match="test failure"),
        isolated_test_runtime() as settings,
    ):
        runtime = settings.src_dir
        raise RuntimeError("test failure")

    assert not runtime.exists()
    assert os.environ["CFMS_TEST_HOST"] == "original-host"
