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
