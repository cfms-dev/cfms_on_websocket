import pytest

TEST_LAYERS = frozenset({"unit", "component", "integration"})


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    violations = []
    for item in items:
        layers = {mark.name for mark in item.iter_markers()} & TEST_LAYERS
        if len(layers) != 1:
            violations.append(
                f"{item.nodeid}: expected exactly one test layer, found {sorted(layers)}"
            )
        elif "integration" not in layers and "server_process" in item.fixturenames:
            violations.append(
                f"{item.nodeid}: server_process requires the integration layer"
            )
    if violations:
        raise pytest.UsageError("Invalid test layers:\n" + "\n".join(violations))
