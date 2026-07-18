import socket

import pytest

from include.transport.client_address import get_bind_options


@pytest.mark.parametrize("host", ["127.0.0.1", "0.0.0.0"])
def test_ipv4_address_uses_ipv4_only_bind_options(host: str):
    family, dualstack_ipv6 = get_bind_options(host, dualstack_ipv6=True)

    assert family == socket.AF_INET
    assert dualstack_ipv6 is False


def test_ipv4_bind_options_create_ipv4_listener():
    family, dualstack_ipv6 = get_bind_options("127.0.0.1", dualstack_ipv6=True)

    with socket.create_server(
        ("127.0.0.1", 0),
        family=family,
        dualstack_ipv6=dualstack_ipv6,
    ) as listener:
        assert listener.family == socket.AF_INET


@pytest.mark.parametrize(
    ("dualstack_ipv6", "expected_dualstack_ipv6"),
    [(False, False), (True, True)],
)
def test_ipv6_address_preserves_dualstack_setting(
    dualstack_ipv6: bool, expected_dualstack_ipv6: bool
):
    family, actual_dualstack_ipv6 = get_bind_options("::1", dualstack_ipv6)

    assert family == socket.AF_INET6
    assert actual_dualstack_ipv6 is expected_dualstack_ipv6
