__all__ = [
    "get_bind_options",
    "get_client_ip",
    "is_v6_address",
    "configure_trusted_proxy_networks",
]

import ipaddress
import socket
from functools import lru_cache

from loguru import logger
from websockets.sync.server import ServerConnection

_DEFAULT_TRUSTED_PROXY_NETWORKS = ("127.0.0.1/32", "::1/128")


def _normalize_ip(value: str) -> str:
    address = ipaddress.ip_address(value.strip())
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped.compressed
    return address.compressed


@lru_cache(maxsize=8)
def _parse_proxy_networks(
    configured: tuple[str, ...],
) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    networks = []
    for value in configured:
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError as exc:
            raise ValueError(f"Invalid trusted proxy network {value!r}") from exc
    return tuple(networks)


_configured_proxy_networks = _parse_proxy_networks(_DEFAULT_TRUSTED_PROXY_NETWORKS)


def configure_trusted_proxy_networks(values) -> None:
    global _configured_proxy_networks
    if isinstance(values, str):
        raise ValueError("server.trusted_proxy_networks must be an array of CIDRs")
    _configured_proxy_networks = _parse_proxy_networks(
        tuple(str(value) for value in values)
    )


def _trusted_proxy_networks():
    return _configured_proxy_networks


def _is_trusted_proxy(
    address: str,
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...],
) -> bool:
    parsed = ipaddress.ip_address(address)
    return any(
        parsed.version == network.version and parsed in network for network in networks
    )


def get_bind_options(
    address: str, dualstack_ipv6: bool
) -> tuple[socket.AddressFamily, bool]:
    """Return a compatible socket family and dual-stack setting for a host."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        family = socket.AF_INET6
    else:
        family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET

    return family, dualstack_ipv6 and family == socket.AF_INET6


def get_client_ip(websocket: ServerConnection) -> str:
    assert websocket.request is not None

    peer_ip = _normalize_ip(websocket.remote_address[0])
    trusted_networks = _trusted_proxy_networks()
    if not _is_trusted_proxy(peer_ip, trusted_networks):
        return peer_ip

    forwarded_for = websocket.request.headers.get("X-Forwarded-For")
    if forwarded_for:
        try:
            forwarded_chain = [
                _normalize_ip(value) for value in forwarded_for.split(",")
            ]
        except ValueError:
            logger.warning("Ignoring invalid X-Forwarded-For header")
            return peer_ip

        for address in reversed([*forwarded_chain, peer_ip]):
            if not _is_trusted_proxy(address, trusted_networks):
                return address
        return forwarded_chain[0] if forwarded_chain else peer_ip

    real_ip = websocket.request.headers.get("X-Real-IP")
    if real_ip:
        try:
            return _normalize_ip(real_ip)
        except ValueError:
            logger.warning("Ignoring invalid X-Real-IP header")

    return peer_ip


def is_v6_address(address):
    try:
        ip = ipaddress.ip_address(address)
        return ip.version == 6
    except ValueError:
        return False
