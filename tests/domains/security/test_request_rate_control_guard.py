from pathlib import Path
from shutil import copyfile
from types import SimpleNamespace

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _prepare_config(monkeypatch, tmp_path):
    copyfile(PROJECT_ROOT / "src" / "config.toml.sample", tmp_path / "config.toml")
    monkeypatch.chdir(tmp_path)


def _use_policy(monkeypatch, guard, policy):
    monkeypatch.setattr(
        guard.RequestRateControlPolicy,
        "from_config",
        classmethod(lambda cls, config=None: policy),
    )


@pytest.mark.parametrize(
    ("mode", "allowed"),
    [("observe", True), ("enforce", False)],
)
def test_request_rate_control_observes_or_enforces_and_hashes_identities(
    monkeypatch, tmp_path, mode, allowed
):
    _prepare_config(monkeypatch, tmp_path)

    from include.config.validation import RequestRateControlPolicy
    from include.domains.security.guards import request_rate_control as guard
    from include.providers.base import RateLimitDecision

    class DenyingProvider:
        def __init__(self):
            self.charges = None

        def consume(self, charges, **_kwargs):
            self.charges = charges
            return RateLimitDecision(
                False,
                scope="account",
                effective_limit=30,
                retry_after_seconds=9,
            )

    provider = DenyingProvider()
    policy = RequestRateControlPolicy(
        mode=mode,
        account_capacity=120,
        account_refill_tokens=120,
        ip_capacity=600,
        ip_refill_tokens=600,
    )
    _use_policy(monkeypatch, guard, policy)
    monkeypatch.setattr(guard, "global_config", {"server": {"secret_key": "secret"}})
    monkeypatch.setattr(
        guard,
        "ProviderManager",
        lambda: SimpleNamespace(rate_limit=provider),
    )

    decision = guard.check_request_rate(
        "search",
        4,
        "192.0.2.55",
        username="alice",
        bypass=False,
    )

    assert decision.allowed is allowed
    assert decision.would_block
    assert decision.scope == "account"
    assert decision.limit == 30
    assert decision.retry_after_seconds == 9
    assert provider.charges is not None
    assert [charge.scope for charge in provider.charges] == ["ip", "account"]
    assert all(charge.cost == 4 for charge in provider.charges)
    assert all("alice" not in charge.key for charge in provider.charges)
    assert all("192.0.2.55" not in charge.key for charge in provider.charges)


def test_request_rate_control_bypass_skips_provider(monkeypatch, tmp_path):
    _prepare_config(monkeypatch, tmp_path)

    from include.domains.security.guards import request_rate_control as guard

    monkeypatch.setattr(
        guard,
        "ProviderManager",
        lambda: (_ for _ in ()).throw(AssertionError("provider must not be used")),
    )

    decision = guard.check_request_rate(
        "search", 1, "192.0.2.55", username="alice", bypass=True
    )

    assert decision.allowed
    assert not decision.would_block


def test_request_rate_control_provider_failure_fails_open(monkeypatch, tmp_path):
    _prepare_config(monkeypatch, tmp_path)

    from include.config.validation import RequestRateControlPolicy
    from include.domains.security.guards import request_rate_control as guard

    class FailingProvider:
        def consume(self, *_args, **_kwargs):
            raise ConnectionError("rate store unavailable")

    _use_policy(monkeypatch, guard, RequestRateControlPolicy(mode="enforce"))
    monkeypatch.setattr(guard, "global_config", {"server": {"secret_key": "secret"}})
    monkeypatch.setattr(
        guard,
        "ProviderManager",
        lambda: SimpleNamespace(rate_limit=FailingProvider()),
    )

    decision = guard.check_connection_attempt("192.0.2.55")

    assert decision.allowed


def test_websocket_upgrade_rate_denial_returns_http_429(monkeypatch, tmp_path):
    _prepare_config(monkeypatch, tmp_path)

    from include.domains.security.guards.request_rate_control import (
        RequestRateControlDecision,
    )
    from include.transport import request_entrypoint

    monkeypatch.setattr(request_entrypoint, "get_client_ip", lambda _conn: "192.0.2.55")
    monkeypatch.setattr(
        request_entrypoint.LoginGuard,
        "evaluate_subnet_access",
        lambda _ip: SimpleNamespace(allowed=True),
    )
    monkeypatch.setattr(
        request_entrypoint,
        "check_connection_attempt",
        lambda _ip: RequestRateControlDecision(False, retry_after_seconds=11),
    )

    response = request_entrypoint.global_process_request(object(), object())

    assert response is not None
    assert response.status_code == 429
    assert response.headers["Retry-After"] == "11"
    assert response.body == b"Too many connection attempts. Please try again later."
