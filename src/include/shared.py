"""
Shared variables across the program.
"""

__all__ = ["clients", "clients_lock"]

import threading

from include.transport.multiplexing import MultiplexedConnection

clients: set[MultiplexedConnection] = set()
clients_lock = threading.Lock()
