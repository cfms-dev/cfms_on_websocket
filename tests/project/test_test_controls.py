import os
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.unit
def test_repository_pytest_configuration_is_active(pytestconfig):
    assert pytestconfig.inipath.name == "pytest.ini"
    assert pytestconfig.getoption("strict_markers")
    assert pytestconfig.getoption("strict_config")
    assert pytestconfig.getini("asyncio_mode") == "strict"
    assert pytestconfig.getini("asyncio_default_fixture_loop_scope") == "function"
    assert float(pytestconfig.getini("timeout")) == 120
    registered_markers = {
        marker.split(":", 1)[0] for marker in pytestconfig.getini("markers")
    }
    assert {"unit", "component", "integration", "stress"} <= registered_markers


@pytest.mark.integration
@pytest.mark.parametrize(
    ("marks", "uses_server", "extra_config", "exit_code", "diagnostic"),
    [
        (["unit"], False, "", 0, "1 passed"),
        (["component"], False, "", 0, "1 passed"),
        (["integration"], True, "", 0, "1 passed"),
        ([], False, "", 4, "expected exactly one test layer"),
        (["unit", "component"], False, "", 4, "expected exactly one test layer"),
        (["unit"], True, "", 4, "server_process requires the integration layer"),
        (["component"], True, "", 4, "server_process requires the integration layer"),
        (["unknown_layer"], False, "", 2, "not found in"),
        (["unit"], False, "unknown_setting = true", 4, "Unknown config option"),
    ],
    ids=[
        "unit",
        "component",
        "integration",
        "missing-layer",
        "conflicting-layers",
        "unit-server",
        "component-server",
        "unknown-marker",
        "unknown-config",
    ],
)
def test_collection_rejects_invalid_test_control(
    tmp_path, marks, uses_server, extra_config, exit_code, diagnostic
):
    config_path = tmp_path / "pytest.ini"
    config_path.write_text(
        "[pytest]\n"
        "addopts = --strict-config --strict-markers\n"
        "markers =\n"
        "    unit: pure logic\n"
        "    component: in-process boundaries\n"
        "    integration: process and network boundaries\n"
        f"{extra_config}\n",
        encoding="utf-8",
    )
    decorators = "\n".join(f"@pytest.mark.{mark}" for mark in marks)
    parameter = "dependent" if uses_server else ""
    (tmp_path / "test_sample.py").write_text(
        "import pytest\n"
        "@pytest.fixture\n"
        "def server_process():\n"
        "    return object()\n"
        "@pytest.fixture\n"
        "def dependent(server_process):\n"
        "    return server_process\n"
        f"{decorators}\n"
        f"def test_sample({parameter}):\n"
        "    assert True\n",
        encoding="utf-8",
    )
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join([str(PROJECT_ROOT), env.get("PYTHONPATH", "")])

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-c",
            str(config_path),
            "-p",
            "tests.support.collection",
            "-q",
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    output = result.stdout + result.stderr
    assert result.returncode == exit_code, output
    assert diagnostic in output
