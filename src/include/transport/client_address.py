__all__ = [
    "get_bind_options",
    "get_client_ip",
]

import ipaddress
import socket

from loguru import logger
from websockets.sync.server import ServerConnection

from include.config.settings import global_config
from include.config.validation import get_trusted_proxy_networks


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    address = ipaddress.ip_address(value.strip())
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped
    return address


def get_bind_options(
    address: str, dualstack_ipv6: bool
) -> tuple[socket.AddressFamily, bool]:
    """Return a compatible socket family and dual-stack setting for a host."""
    family = socket.AddressFamily(
        socket.getaddrinfo(
            address,
            None,
            type=socket.SOCK_STREAM,
            flags=socket.AI_PASSIVE,
        )[0][0]
    )

    return family, dualstack_ipv6 and family == socket.AF_INET6


def get_client_ip(websocket: ServerConnection) -> str:
    assert websocket.request is not None

    peer_address = _parse_ip(websocket.remote_address[0])
    trusted_networks = get_trusted_proxy_networks(global_config)
    if not any(peer_address in network for network in trusted_networks):
        return str(peer_address)

    forwarded_for = websocket.request.headers.get("X-Forwarded-For")
    if forwarded_for:
        try:
            forwarded_chain = [_parse_ip(value) for value in forwarded_for.split(",")]
        except ValueError:
            logger.warning("Ignoring invalid X-Forwarded-For header")
            return str(peer_address)

        for address in reversed([*forwarded_chain, peer_address]):
            if not any(address in network for network in trusted_networks):
                return str(address)
        return str(forwarded_chain[0]) if forwarded_chain else str(peer_address)

    real_ip = websocket.request.headers.get("X-Real-IP")
    if real_ip:
        try:
            return str(_parse_ip(real_ip))
        except ValueError:
            logger.warning("Ignoring invalid X-Real-IP header")

    return str(peer_address)
