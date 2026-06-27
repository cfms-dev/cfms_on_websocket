__all__ = ["get_client_ip", "is_v6_address"]

import ipaddress

from websockets.sync.server import ServerConnection

from include.config.constants import TRUSTED_PROXY_IPS


def get_client_ip(websocket: ServerConnection) -> str:
    assert websocket.request is not None

    # The actual TCP peer address of the websocket connection.
    peer_ip = websocket.remote_address[0]

    # Only trust forwarding headers if the TCP peer is a known reverse proxy.
    if peer_ip in TRUSTED_PROXY_IPS:
        forwarded_for = websocket.request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        real_ip = websocket.request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()

    # Fallback to the peer IP when no trusted proxy is involved or no headers are present.
    return peer_ip


def is_v6_address(address):
    try:
        ip = ipaddress.ip_address(address)
        return ip.version == 6
    except ValueError:
        return False
