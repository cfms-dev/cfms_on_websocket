from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_release_smoke_prepares_dependencies_outside_the_test_timeout():
    workflow = yaml.safe_load(
        (PROJECT_ROOT / ".github" / "workflows" / "test.yml").read_text(
            encoding="utf-8"
        )
    )
    steps = workflow["jobs"]["release-bundle-smoke"]["steps"]
    test_index, test_step = next(
        (index, step)
        for index, step in enumerate(steps)
        if "pytest tests/database/test_file_writeable.py" in step.get("run", "")
    )
    install_steps = [
        step
        for step in steps[:test_index]
        if step.get("run") == "uv sync --locked --dev"
    ]

    assert len(install_steps) == 1
    install_step = install_steps[0]
    assert "if" not in install_step
    assert test_step["timeout-minutes"] == 3
    assert install_step["timeout-minutes"] > test_step["timeout-minutes"]
    assert "--no-sync" in test_step["run"].split()


def test_redis_provider_behavior_job_enables_real_service_tests():
    workflow = yaml.safe_load(
        (PROJECT_ROOT / ".github" / "workflows" / "test.yml").read_text(
            encoding="utf-8"
        )
    )
    job = workflow["jobs"]["redis-provider-behavior"]
    assert "if" not in job
    service = job["services"]["redis"]
    assert service["image"] == "redis:8.2.10-alpine"
    assert service["ports"] == ["6379:6379"]
    assert '--health-cmd="redis-cli ping"' in service["options"]
    install_index, install_step = next(
        (index, step)
        for index, step in enumerate(job["steps"])
        if step.get("run", "").startswith("uv sync ")
    )
    test_index, test_step = next(
        (index, step)
        for index, step in enumerate(job["steps"])
        if "pytest tests/providers/test_redis_lua_integration.py" in step.get("run", "")
    )
    assert install_index < test_index
    assert install_step["run"] == (
        "uv sync --locked --dev --extra cluster --extra ext-scheduling-cluster"
    )
    assert "if" not in install_step
    assert "if" not in test_step
    assert test_step["env"]["CFMS_TEST_REDIS_URL"] == "redis://127.0.0.1:6379/0"
    assert test_step["run"] == (
        "uv run --locked pytest tests/providers/test_redis_lua_integration.py -q"
    )
    assert test_step["timeout-minutes"] == 5
