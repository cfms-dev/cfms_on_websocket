__all__ = [
    "get_bind_options",
    "get_client_ip",
    "is_v6_address",
]

import ipaddress
import socket

from loguru import logger
from websockets.sync.server import ServerConnection

from include.config.settings import global_config
from include.config.validation import get_trusted_proxy_networks


def _normalize_ip(value: str) -> str:
    address = ipaddress.ip_address(value.strip())
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped.compressed
    return address.compressed


def _is_trusted_proxy(
    address: str,
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...],
) -> bool:
    parsed = ipaddress.ip_address(address)
    return any(parsed in network for network in networks)


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
    trusted_networks = get_trusted_proxy_networks(global_config)
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
