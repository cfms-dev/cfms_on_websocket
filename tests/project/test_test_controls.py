import json
import os
import subprocess
import sys
from pathlib import Path
from shutil import copyfile
from xml.etree import ElementTree as ET

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
    assert "no:randomly" in pytestconfig.getini("addopts")
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


@pytest.mark.integration
@pytest.mark.parametrize("worker", ["thread", "finalizer"])
def test_unhandled_worker_or_finalizer_errors_fail_the_run(tmp_path, worker):
    source = (
        "import threading\nimport gc\nimport pytest\n"
        "def fail():\n    raise RuntimeError('worker failed')\n"
        "class Broken:\n    def __del__(self):\n        fail()\n"
        "@pytest.mark.unit\ndef test_probe():\n"
    )
    if worker == "thread":
        source += "    worker = threading.Thread(target=fail)\n    worker.start()\n    worker.join(timeout=2)\n"
    else:
        source += "    value = Broken()\n    del value\n    gc.collect()\n"
    probe = tmp_path / "test_probe.py"
    probe.write_text(source, encoding="utf-8")
    report = tmp_path / "probe.xml"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-c",
            str(PROJECT_ROOT / "pytest.ini"),
            str(probe),
            "-q",
            f"--junitxml={report}",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    cases = ET.parse(report).findall(".//testcase")
    assert len(cases) == 1
    assert cases[0].find("failure") is not None or cases[0].find("error") is not None


@pytest.mark.integration
def test_health_command_runs_without_git_history_or_calibration_files(tmp_path):
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    command = tools_dir / "check_test_health.py"
    copyfile(PROJECT_ROOT / "tools/check_test_health.py", command)
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_probe.py").write_text(
        "import pytest\n@pytest.mark.unit\ndef test_probe():\n    assert sum((1, 2)) == 3\n",
        encoding="utf-8",
    )
    (tmp_path / "pytest.ini").write_text(
        "[pytest]\nmarkers =\n    unit: pure logic\n", encoding="utf-8"
    )
    report = tmp_path / "result.xml"
    result = subprocess.run(
        [
            sys.executable,
            str(command),
            "run",
            "--profile",
            "unit",
            "--report",
            str(report),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    summary = json.loads(report.with_suffix(".json").read_text(encoding="utf-8"))
    assert summary["executed"] == 1
    assert summary["returncode"] == summary["pytest_returncode"] == 0
    assert summary["limit_seconds"] == 30
