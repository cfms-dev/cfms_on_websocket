import os
from shutil import copyfile

import pytest
from tomlkit import parse

from tests.support.config import SOURCE_ROOT, managed_test_config


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


@pytest.mark.parametrize("raise_during_test", [False, True])
def test_managed_test_config_restores_existing_config_exactly(
    tmp_path, raise_during_test
):
    src_dir = tmp_path / "src"
    _copy_config_sample(src_dir)
    config_path = src_dir / "config.toml"
    original = b'[operator]\nvalue = "preserve exactly"\n'
    config_path.write_bytes(original)

    if raise_during_test:
        with pytest.raises(RuntimeError, match="test failure"):
            with managed_test_config(src_dir):
                config_path.write_bytes(b"changed")
                raise RuntimeError("test failure")
    else:
        with managed_test_config(src_dir):
            config_path.write_bytes(b"changed")

    assert config_path.read_bytes() == original
