__all__ = ["AdmissionController", "AdmissionDecision", "admission_controller"]

import threading
from dataclasses import dataclass

from include.config.validation import AdmissionControlPolicy


@dataclass(frozen=True, slots=True)
class AdmissionDecision:
    allowed: bool
    scope: str | None = None
    retry_after_seconds: int = 0


class AdmissionController:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._connections = 0
        self._connections_by_ip: dict[str, int] = {}
        self._requests = 0
        self._requests_by_connection: dict[object, int] = {}

    def acquire_connection(self, ip_address: str) -> AdmissionDecision:
        policy = AdmissionControlPolicy.from_config()
        with self._lock:
            if self._connections >= policy.max_connections:
                return AdmissionDecision(
                    False, "server_connections", policy.busy_retry_after_seconds
                )
            ip_connections = self._connections_by_ip.get(ip_address, 0)
            if ip_connections >= policy.max_connections_per_ip:
                return AdmissionDecision(
                    False, "ip_connections", policy.busy_retry_after_seconds
                )
            self._connections += 1
            self._connections_by_ip[ip_address] = ip_connections + 1
        return AdmissionDecision(True)

    def release_connection(self, ip_address: str) -> None:
        with self._lock:
            self._connections -= 1
            remaining = self._connections_by_ip[ip_address] - 1
            if remaining:
                self._connections_by_ip[ip_address] = remaining
            else:
                del self._connections_by_ip[ip_address]

    def acquire_request(self, connection: object) -> AdmissionDecision:
        policy = AdmissionControlPolicy.from_config()
        with self._lock:
            if self._requests >= policy.max_inflight_requests:
                return AdmissionDecision(
                    False, "server_concurrency", policy.busy_retry_after_seconds
                )
            connection_requests = self._requests_by_connection.get(connection, 0)
            if connection_requests >= policy.max_inflight_requests_per_connection:
                return AdmissionDecision(
                    False, "connection_concurrency", policy.busy_retry_after_seconds
                )
            self._requests += 1
            self._requests_by_connection[connection] = connection_requests + 1
        return AdmissionDecision(True)

    def release_request(self, connection: object) -> None:
        with self._lock:
            self._requests -= 1
            remaining = self._requests_by_connection[connection] - 1
            if remaining:
                self._requests_by_connection[connection] = remaining
            else:
                del self._requests_by_connection[connection]


admission_controller = AdmissionController()
