from include.config.validation import AdmissionControlPolicy
from include.transport import admission as admission_module
from include.transport.admission import AdmissionController


def _policy(**overrides: int) -> AdmissionControlPolicy:
    values = {
        "max_connections": 2,
        "max_connections_per_ip": 1,
        "max_inflight_requests": 2,
        "max_inflight_requests_per_connection": 1,
        "max_pending_streams_per_connection": 2,
        "busy_retry_after_seconds": 3,
    }
    values.update(overrides)
    return AdmissionControlPolicy(**values)


def _use_policy(monkeypatch, policy: AdmissionControlPolicy) -> None:
    monkeypatch.setattr(
        admission_module.AdmissionControlPolicy,
        "from_config",
        classmethod(lambda cls, config=None: policy),
    )


def test_connection_admission_enforces_ip_and_server_caps(monkeypatch):
    _use_policy(monkeypatch, _policy())
    controller = AdmissionController()

    assert controller.acquire_connection("192.0.2.1").allowed
    ip_denial = controller.acquire_connection("192.0.2.1")
    assert not ip_denial.allowed
    assert ip_denial.scope == "ip_connections"
    assert ip_denial.retry_after_seconds == 3

    assert controller.acquire_connection("192.0.2.2").allowed
    server_denial = controller.acquire_connection("192.0.2.3")
    assert not server_denial.allowed
    assert server_denial.scope == "server_connections"

    controller.release_connection("192.0.2.1")
    assert controller.acquire_connection("192.0.2.3").allowed


def test_request_admission_releases_capacity_after_completion(monkeypatch):
    _use_policy(monkeypatch, _policy())
    controller = AdmissionController()
    first_connection = object()
    second_connection = object()

    assert controller.acquire_request(first_connection).allowed
    connection_denial = controller.acquire_request(first_connection)
    assert not connection_denial.allowed
    assert connection_denial.scope == "connection_concurrency"

    assert controller.acquire_request(second_connection).allowed
    server_denial = controller.acquire_request(object())
    assert not server_denial.allowed
    assert server_denial.scope == "server_concurrency"

    controller.release_request(first_connection)
    assert controller.acquire_request(first_connection).allowed
