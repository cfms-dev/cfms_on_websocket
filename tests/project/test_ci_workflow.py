import shlex
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.component

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_main_ci_runs_every_test_layer_and_retains_junit_reports():
    workflow = yaml.safe_load(
        (PROJECT_ROOT / ".github" / "workflows" / "test.yml").read_text(
            encoding="utf-8"
        )
    )
    steps = workflow["jobs"]["test"]["steps"]
    commands = [
        step["run"] for step in steps if "pytest tests/ -m " in step.get("run", "")
    ]

    assert len(commands) == 3
    for layer, command in zip(
        ("unit", "component", "integration"), commands, strict=True
    ):
        arguments = shlex.split(command)
        assert arguments[:5] == ["uv", "run", "--locked", "pytest", "tests/"]
        assert arguments[arguments.index("-m") + 1] == f"{layer} and not stress"
        assert f"--junitxml=test-results/{layer}.xml" in command
        assert "--durations=25" in command
    artifact = next(step for step in steps if step.get("name") == "Upload test results")
    assert artifact["if"] == "always()"
    assert "test-results/" in artifact["with"]["path"].splitlines()


@pytest.mark.parametrize(
    ("job_name", "environment", "report", "required_paths", "selector"),
    [
        (
            "redis-provider-behavior",
            "CFMS_TEST_REDIS_URL",
            "redis",
            ("tests/providers/test_redis_lua_integration.py",),
            None,
        ),
        (
            "mysql-database-migration",
            "CFMS_TEST_MYSQL_URL",
            "mysql",
            (
                "tests/scheduling/test_engine_shared_database.py",
                "tests/scheduling/test_engine.py::test_runtime_state_initialization_is_atomic_on_shared_database",
                "tests/domains/documents/test_upload_cleanup_mysql.py",
                "tests/domains/documents/test_rate_limits_mysql.py",
                "tests/maintenance/database/test_mysql.py",
            ),
            "mysql",
        ),
        (
            "postgresql-scheduling-concurrency",
            "CFMS_TEST_POSTGRESQL_URL",
            "postgresql",
            (
                "tests/scheduling/test_engine_shared_database.py",
                "tests/scheduling/test_engine.py::test_runtime_state_initialization_is_atomic_on_shared_database",
            ),
            "postgresql",
        ),
    ],
)
def test_backend_ci_requires_real_execution_without_skips(
    job_name,
    environment,
    report,
    required_paths,
    selector,
):
    workflow = yaml.safe_load(
        (PROJECT_ROOT / ".github" / "workflows" / "test.yml").read_text(
            encoding="utf-8"
        )
    )
    job = workflow["jobs"][job_name]
    test_step = next(step for step in job["steps"] if "pytest " in step.get("run", ""))
    command = test_step["run"]
    assert test_step["env"][environment]
    assert f'test -n "${environment}"' in command
    for path in required_paths:
        assert path in command.split()
    if selector is not None:
        assert f"-k {selector}" in command
    assert f"--junitxml=test-results/{report}.xml" in command
    verification = next(
        step["run"] for step in job["steps"] if "ET.parse(" in step.get("run", "")
    )
    assert f"test-results/{report}.xml" in verification
    assert "assert cases" in verification
    assert "case.find('skipped') is None" in verification
    artifact = next(
        step for step in job["steps"] if "upload-artifact@" in step.get("uses", "")
    )
    assert artifact["if"] == "always()"
    assert artifact["with"]["path"] == "test-results/"
