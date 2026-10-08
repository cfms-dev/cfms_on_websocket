import pytest

pytestmark = pytest.mark.unit


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
