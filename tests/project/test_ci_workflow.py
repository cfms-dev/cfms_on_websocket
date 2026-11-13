import os
import shlex
import subprocess
from pathlib import Path

import pytest
import yaml

from tools.check_test_health import PROFILES

PROJECT_ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.component
def test_main_ci_runs_every_test_layer_and_retains_junit_reports():
    workflow = yaml.safe_load(
        (PROJECT_ROOT / ".github" / "workflows" / "test.yml").read_text(
            encoding="utf-8"
        )
    )
    job = workflow["jobs"]["test-layer"]
    assert job["if"] == (
        "github.event_name != 'schedule' && github.event_name != 'workflow_dispatch'"
    )
    assert "needs" not in job
    assert job["strategy"]["fail-fast"] is False
    layers = job["strategy"]["matrix"]["layer"]
    assert layers == ["unit", "component", "integration"]
    steps = job["steps"]
    channels = [
        step for step in steps if "check_test_health.py run " in step.get("run", "")
    ]
    assert len(channels) == 1
    step = channels[0]
    assert step["env"]["TEST_COMMIT"] == "${{ github.sha }}"
    assert step["env"]["TEST_LAYER"] == "${{ matrix.layer }}"
    assert "int(os.environ['TEST_COMMIT'][:8], 16)" in step["run"]
    command = next(
        line for line in step["run"].splitlines() if "check_test_health.py run " in line
    )
    for layer in layers:
        arguments = shlex.split(
            command.replace("${TEST_LAYER}", layer).replace("$TEST_LAYER", layer)
        )
        assert arguments[:5] == [
            "uv",
            "run",
            "--locked",
            "python",
            "tools/check_test_health.py",
        ]
        assert arguments[arguments.index("--profile") + 1] == layer
        assert PROFILES[layer] == ["tests/", "-m", f"{layer} and not stress"]
        assert arguments[arguments.index("--report") + 1] == f"test-results/{layer}.xml"
        assert arguments[arguments.index("--seed") + 1] == "$seed"
        assert step["timeout-minutes"] == 10
    changelog = [
        step for step in steps if step.get("name") == "Check changelog fragment"
    ]
    assert len(changelog) == 1
    assert "matrix.layer == 'unit'" in changelog[0]["if"]
    artifact = next(step for step in steps if step.get("name") == "Upload test results")
    assert artifact["if"] == "always()"
    assert "test-results/" in artifact["with"]["path"].splitlines()
    assert "${{ matrix.layer }}" in artifact["with"]["name"]


@pytest.mark.integration
@pytest.mark.parametrize("result", ["success", "failure", "cancelled", "skipped"])
def test_summary_check_rejects_every_unsuccessful_layer(result):
    workflow = yaml.safe_load(
        (PROJECT_ROOT / ".github/workflows/test.yml").read_text(encoding="utf-8")
    )
    job = workflow["jobs"]["test"]
    assert job["needs"] == "test-layer"
    assert job["if"] == f"always() && {workflow['jobs']['test-layer']['if']}"
    assert job["strategy"]["matrix"] == {"python-version": ["3.15"]}
    (step,) = job["steps"]
    assert step["env"]["LAYER_RESULT"] == "${{ needs.test-layer.result }}"
    environment = os.environ.copy()
    environment["LAYER_RESULT"] = result
    completed = subprocess.run(
        [step["shell"], "-NoProfile", "-NonInteractive", "-Command", step["run"]],
        env=environment,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert completed.returncode == (0 if result == "success" else 1), (
        completed.stdout + completed.stderr
    )


@pytest.mark.component
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
    test_step = next(
        step
        for step in job["steps"]
        if "check_test_health.py run " in step.get("run", "")
    )
    assert test_step["env"][environment]
    command = shlex.split(test_step["run"])
    profile = command[command.index("--profile") + 1]
    if report == "mysql":
        assert profile == "mysql-${{ matrix.mysql-version }}"
        profile = "mysql-8.4"
    arguments = PROFILES[profile]
    assert all(path in arguments for path in required_paths)
    if selector is not None:
        assert arguments[arguments.index("-k") + 1] == selector
    assert command[command.index("--report") + 1] == f"test-results/{report}.xml"
    artifact = next(
        step for step in job["steps"] if "upload-artifact@" in step.get("uses", "")
    )
    assert artifact["if"] == "always()"
    assert artifact["with"]["path"] == "test-results/"


@pytest.mark.component
def test_first_ci_keeps_daily_order_checks_and_runs_independent_nodes_once():
    workflow = yaml.safe_load(
        (PROJECT_ROOT / ".github/workflows/test.yml").read_text(encoding="utf-8")
    )
    daily = workflow["jobs"]["first-daily"]
    independent = workflow["jobs"]["first-independent"]
    daily_condition = (
        "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'"
    )
    assert daily["if"] == independent["if"] == daily_condition
    assert daily["strategy"]["matrix"]["seed"] == [1, 17, 101]
    assert daily["strategy"]["fail-fast"] is False
    assert set(daily["services"]) == {"mysql", "postgresql", "redis", "s3"}
    shuffled = [
        step for step in daily["steps"] if "--profile all" in step.get("run", "")
    ]
    assert len(shuffled) == 1
    assert "--seed ${{ matrix.seed }}" in shuffled[0]["run"]
    isolation = [
        (name, step)
        for name, job in workflow["jobs"].items()
        for step in job["steps"]
        if "check_test_health.py isolate " in step.get("run", "")
    ]
    assert len(isolation) == 1
    assert isolation[0][0] == "first-independent"
    assert "strategy" not in independent
    for job in (daily, independent):
        artifact = next(
            step for step in job["steps"] if "upload-artifact@" in step.get("uses", "")
        )
        assert artifact["if"] == "always()"
        assert "test-results/" in artifact["with"]["path"].splitlines()
    triggers = workflow.get("on", workflow.get(True))
    assert triggers["schedule"]


@pytest.mark.component
def test_s3_ci_uses_a_disposable_service_and_explicit_configuration():
    workflow = yaml.safe_load(
        (PROJECT_ROOT / ".github/workflows/test.yml").read_text(encoding="utf-8")
    )
    job = workflow["jobs"]["s3-provider-behavior"]
    assert job["services"]["s3"]["image"] == "chrislusf/seaweedfs:4.53"
    assert job["env"]["CFMS_TEST_S3_WRITE"] == "1"
    assert (
        job["env"]["CFMS_TEST_S3_BUCKET"] == job["services"]["s3"]["env"]["S3_BUCKET"]
    )
    assert job["env"]["CFMS_TEST_S3_ENDPOINT_URL"] == "http://127.0.0.1:8333"
    assert any('--profile "s3"' in step.get("run", "") for step in job["steps"])
