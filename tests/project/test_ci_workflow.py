from pathlib import Path

import pytest
import yaml

from tools.check_test_health import PROFILES

pytestmark = pytest.mark.component

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_main_ci_runs_every_test_layer_and_retains_junit_reports():
    workflow = yaml.safe_load(
        (PROJECT_ROOT / ".github" / "workflows" / "test.yml").read_text(
            encoding="utf-8"
        )
    )
    steps = workflow["jobs"]["test"]["steps"]
    channels = [
        step for step in steps if step.get("uses") == "./.github/actions/test-health"
    ]
    assert [step["with"]["profile"] for step in channels] == [
        "unit",
        "component",
        "integration",
    ]
    for layer, step in zip(("unit", "component", "integration"), channels, strict=True):
        assert PROFILES[layer] == ["tests/", "-m", f"{layer} and not stress"]
        assert step["with"]["report"] == f"test-results/{layer}.xml"
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
    test_step = next(
        step
        for step in job["steps"]
        if step.get("uses") == "./.github/actions/test-health"
    )
    assert test_step["env"][environment]
    profile = test_step["with"]["profile"]
    if report == "mysql":
        assert profile == "mysql-${{ matrix.mysql-version }}"
        profile = "mysql-8.4"
    arguments = PROFILES[profile]
    assert all(path in arguments for path in required_paths)
    if selector is not None:
        assert arguments[arguments.index("-k") + 1] == selector
    assert test_step["with"]["report"] == f"test-results/{report}.xml"
    artifact = next(
        step for step in job["steps"] if "upload-artifact@" in step.get("uses", "")
    )
    assert artifact["if"] == "always()"
    assert artifact["with"]["path"] == "test-results/"


def test_first_ci_keeps_reference_budgets_and_reproducible_order_checks():
    workflow = yaml.safe_load(
        (PROJECT_ROOT / ".github/workflows/test.yml").read_text(encoding="utf-8")
    )
    action = yaml.safe_load(
        (PROJECT_ROOT / ".github/actions/test-health/action.yml").read_text(
            encoding="utf-8"
        )
    )
    steps = action["runs"]["steps"]
    calibration = next(
        step for step in steps if "calibrate --profile" in step.get("run", "")
    )
    assert calibration["if"] == "steps.cache.outputs.cache-hit != 'true'"
    assert "--root .first-baseline" in calibration["run"]
    checkout = next(
        step for step in steps if step.get("uses", "").startswith("actions/checkout@")
    )
    assert checkout["with"]["ref"] == "${{ steps.baseline.outputs.reference }}"
    assert "--baseline" in steps[-1]["run"]
    main_steps = workflow["jobs"]["test"]["steps"]
    shuffled = next(step for step in main_steps if "--seed" in step.get("run", ""))
    assert shuffled["env"]["TEST_COMMIT"] == "${{ github.sha }}"
    assert "--profile all" in shuffled["run"]
    daily = workflow["jobs"]["first-daily"]
    assert daily["strategy"]["matrix"]["seed"] == [1, 17, 101]
    assert set(daily["services"]) == {"mysql", "postgresql", "redis", "s3"}
    assert any(" isolate " in step.get("run", "") for step in daily["steps"])
    triggers = workflow.get("on", workflow.get(True))
    assert triggers["schedule"]


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
    assert any(step.get("with", {}).get("profile") == "s3" for step in job["steps"])
