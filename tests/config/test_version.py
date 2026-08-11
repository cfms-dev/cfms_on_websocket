import pytest

from include.config.version import Version


@pytest.mark.parametrize(
    "version",
    [
        "1.2.3suffix",
        "1.2.3_preview",
        "1.2.3-alpha",
        "1.2",
        "1.2.3.4.5",
    ],
)
def test_version_rejects_invalid_complete_strings(version):
    with pytest.raises(ValueError, match="Invalid version string"):
        Version(version)


def test_version_orders_numeric_components():
    assert Version("1.2.3") < Version("1.2.3.1")
    assert Version("1.2.3.1") < Version("1.2.4")
    assert Version("1.2.4") < Version("1.3.0")
    assert Version("1.3.0") < Version("2.0.0")


def test_version_orders_release_stages():
    assert Version("1.2.3_alpha") < Version("1.2.3_beta")
    assert Version("1.2.3_beta") < Version("1.2.3_rc")
    assert Version("1.2.3_rc") < Version("1.2.3")
    assert Version("1.2.3_release") == Version("1.2.3")


def test_version_orders_stage_numbers():
    assert Version("1.2.3_alpha") < Version("1.2.3_alpha1")
    assert Version("1.2.3_alpha1") < Version("1.2.3_alpha2")


def test_version_release_types_are_case_insensitive():
    assert Version("1.2.3_ALPHA1") == Version("1.2.3_alpha1")
