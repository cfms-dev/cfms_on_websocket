import argparse
import ssl
import sys
from pathlib import Path

import pytest

from tests.stress.ws_load import (
    FixedRatePacer,
    LoadStats,
    create_load_ssl_context,
    parse_args,
    resolve_credentials,
    summarize,
)
from tests.support import client as client_module
from tests.support.client import CFMSTestClient


def test_managed_load_test_disables_debug_by_default(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["ws_load.py", "--managed-reset"])

    args = parse_args()

    assert args.debug is False
    assert args.users == 8


def test_managed_load_test_can_enable_debug(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["ws_load.py", "--managed-reset", "--debug"])

    args = parse_args()

    assert args.debug is True


@pytest.mark.parametrize(
    "arguments",
    [
        ["--users", "0"],
        ["--duration", "0"],
        ["--duration", "5", "--ramp-up", "5"],
        ["--rate", "-1"],
        ["--no-ssl", "--insecure"],
        ["--insecure", "--tls-ca-file", "ca.pem"],
    ],
)
def test_load_test_rejects_invalid_parameters(monkeypatch, arguments):
    monkeypatch.setattr(sys, "argv", ["ws_load.py", *arguments])

    with pytest.raises(SystemExit):
        parse_args()


def test_load_stats_report_total_and_per_action_metrics():
    stats = LoadStats()
    stats.record_success("server_info", 10)
    stats.record_error("server_info", "code_503", 20)
    stats.record_success("list_users", 30)
    stats.dropped_iterations = 2

    result = summarize(stats, elapsed=2, scenario="mixed", users=3)

    assert result["requests"] == 3
    assert result["successes"] == 2
    assert result["success_rate"] == pytest.approx(2 / 3, abs=0.0001)
    assert result["throughput_rps"] == 1.5
    assert result["dropped_iterations"] == 2
    assert result["actions"]["server_info"]["errors"] == {"code_503": 1}
    assert result["actions"]["list_users"]["latency_ms"]["p95"] == 30


def test_upload_action_metrics_can_be_separate_from_iteration_metrics():
    stats = LoadStats()
    stats.record_success("create_document", 10, include_in_total=False)
    stats.record_success("upload_file", 20, include_in_total=False)
    stats.record_iteration_success(35)

    result = summarize(stats, elapsed=1, scenario="upload-unique", users=1)

    assert result["requests"] == 1
    assert result["latency_ms"]["p95"] == 35
    assert result["actions"]["create_document"]["latency_ms"]["p95"] == 10
    assert result["actions"]["upload_file"]["latency_ms"]["p95"] == 20


def test_fixed_rate_pacer_reports_saturated_slots():
    pacer = FixedRatePacer(next_start=10, interval=1, deadline=15)

    assert pacer.next_slot(10.2) == (10, 0)
    assert pacer.next_slot(13.2) == (13, 2)
    assert pacer.next_slot(14) == (14, 0)
    assert pacer.next_slot(15) == (None, 0)


def test_fixed_rate_pacer_excludes_floating_point_deadline_slot():
    pacer = FixedRatePacer(next_start=100, interval=0.2, deadline=101)
    scheduled = []

    while True:
        slot, _dropped = pacer.next_slot(pacer.next_start)
        if slot is None:
            break
        scheduled.append(slot)

    assert len(scheduled) == 5


def test_remote_credentials_come_from_explicit_non_secret_inputs(monkeypatch):
    monkeypatch.setenv("CFMS_LOAD_USERNAME", "load-user")
    monkeypatch.setenv("PRIVATE_LOAD_PASSWORD", "secret")
    args = argparse.Namespace(
        scenario="mixed",
        username=None,
        password_env="PRIVATE_LOAD_PASSWORD",
    )

    credentials = resolve_credentials(args, managed=False, src_dir=Path("src"))

    assert credentials is not None
    assert credentials.username == "load-user"
    assert credentials.password == "secret"
    assert "secret" not in repr(credentials)


def test_remote_authenticated_scenario_requires_credentials(monkeypatch):
    monkeypatch.delenv("CFMS_LOAD_USERNAME", raising=False)
    monkeypatch.delenv("CFMS_LOAD_PASSWORD", raising=False)
    args = argparse.Namespace(
        scenario="auth-read",
        username=None,
        password_env="CFMS_LOAD_PASSWORD",
    )

    with pytest.raises(RuntimeError, match="Remote authenticated scenarios require"):
        resolve_credentials(args, managed=False, src_dir=Path("src"))


def test_remote_tls_verification_is_enabled_by_default():
    context = create_load_ssl_context(
        use_ssl=True,
        managed=False,
        insecure=False,
        tls_ca_file=None,
    )

    assert context is not None
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED


def test_managed_tls_allows_the_disposable_self_signed_certificate():
    context = create_load_ssl_context(
        use_ssl=True,
        managed=True,
        insecure=False,
        tls_ca_file=None,
    )

    assert context is not None
    assert context.check_hostname is False
    assert context.verify_mode == ssl.CERT_NONE


@pytest.mark.asyncio
async def test_client_uses_caller_owned_ssl_context(monkeypatch):
    observed = {}
    expected_context = ssl.create_default_context()

    async def connect(uri, **kwargs):
        observed["uri"] = uri
        observed.update(kwargs)
        return object()

    monkeypatch.setattr(client_module, "connect", connect)
    monkeypatch.setattr(
        client_module, "AsyncMultiplexConnection", lambda _websocket: object()
    )
    client = CFMSTestClient(
        host="example.test",
        port=443,
        use_ssl=True,
        ssl_context=expected_context,
    )

    await client.connect()

    assert observed["uri"] == "wss://example.test:443"
    assert observed["ssl"] is expected_context
