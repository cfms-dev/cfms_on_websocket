import socket
from types import SimpleNamespace

import pytest

from include.transport import client_address
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


def _websocket(peer_ip: str, headers: dict[str, str]):
    return SimpleNamespace(
        remote_address=(peer_ip, 5104),
        request=SimpleNamespace(headers=headers),
    )


def test_untrusted_peer_cannot_spoof_forwarded_address(monkeypatch):
    monkeypatch.setattr(client_address, "_trusted_proxy_networks", lambda: ())
    websocket = _websocket("198.51.100.20", {"X-Forwarded-For": "203.0.113.99"})

    assert client_address.get_client_ip(websocket) == "198.51.100.20"


def test_forwarded_chain_uses_rightmost_untrusted_address(monkeypatch):
    networks = client_address._parse_proxy_networks(("10.0.0.0/8",))
    monkeypatch.setattr(client_address, "_trusted_proxy_networks", lambda: networks)
    websocket = _websocket(
        "10.0.0.2",
        {"X-Forwarded-For": "192.0.2.123, 198.51.100.7, 10.0.0.1"},
    )

    assert client_address.get_client_ip(websocket) == "198.51.100.7"


def test_invalid_forwarded_chain_falls_back_to_peer(monkeypatch):
    networks = client_address._parse_proxy_networks(("10.0.0.0/8",))
    monkeypatch.setattr(client_address, "_trusted_proxy_networks", lambda: networks)
    websocket = _websocket("10.0.0.2", {"X-Forwarded-For": "not-an-ip"})

    assert client_address.get_client_ip(websocket) == "10.0.0.2"


def test_ipv4_mapped_ipv6_address_is_canonicalized(monkeypatch):
    monkeypatch.setattr(client_address, "_trusted_proxy_networks", lambda: ())
    websocket = _websocket("::ffff:192.0.2.10", {})

    assert client_address.get_client_ip(websocket) == "192.0.2.10"
