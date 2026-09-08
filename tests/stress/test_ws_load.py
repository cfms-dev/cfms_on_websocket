import argparse
import asyncio
import base64
import json
import ssl
import sys
import time
from pathlib import Path

import orjson
import pytest

from tests.stress.load_config import load_profiles, normalized_parameters
from tests.stress.load_metrics import (
    BoundedLatencyHistogram,
    ConnectionStats,
    GeneratorHealth,
    current_rss_bytes,
    monitor_generator,
)
from tests.stress.ws_load import (
    FixedRatePacer,
    LoadStats,
    build_phases,
    create_load_ssl_context,
    load_account_pool,
    parse_args,
    resolve_credentials,
    summarize,
    timed_call,
)
from tests.support import client as client_module
from tests.support.client import CFMSTestClient


def test_managed_load_test_disables_debug_by_default(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["ws_load.py", "--managed-reset"])

    args = parse_args()

    assert args.debug is False
    assert args.users == 2


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


def test_fixed_global_arrival_rate_uses_the_full_scheduling_window():
    pacers = [
        FixedRatePacer(next_start=100 + worker / 10, interval=0.2, deadline=102)
        for worker in range(2)
    ]
    stats = LoadStats()
    for pacer in pacers:
        while True:
            slot, _ = pacer.next_slot(pacer.next_start)
            if slot is None:
                break
            stats.record_success("server_info", 1)

    result = summarize(stats, elapsed=2, scenario="server-info", users=2)

    assert result["requests"] == 20
    assert result["throughput_rps"] == 10


def test_remote_credentials_come_from_explicit_non_secret_inputs(monkeypatch):
    monkeypatch.setenv("CFMS_LOAD_USERNAME", "load-user")
    monkeypatch.setenv("PRIVATE_LOAD_PASSWORD", "secret")
    args = argparse.Namespace(
        scenario="mixed",
        username=None,
        password_env="PRIVATE_LOAD_PASSWORD",
        accounts_file=None,
    )

    credentials = resolve_credentials(args, managed=False, src_dir=Path("src"))

    assert len(credentials) == 1
    assert credentials[0].username == "load-user"
    assert credentials[0].password == "secret"
    assert "secret" not in repr(credentials)


def test_remote_authenticated_scenario_requires_credentials(monkeypatch):
    monkeypatch.delenv("CFMS_LOAD_USERNAME", raising=False)
    monkeypatch.delenv("CFMS_LOAD_PASSWORD", raising=False)
    args = argparse.Namespace(
        scenario="auth-read",
        username=None,
        password_env="CFMS_LOAD_PASSWORD",
        accounts_file=None,
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


def test_required_profiles_are_valid_and_normalized():
    profiles = load_profiles()

    assert {"smoke", "peak", "stress", "spike", "soak"} <= profiles.keys()
    assert profiles["stress"].stage_rates == tuple(
        sorted(profiles["stress"].stage_rates)
    )
    assert profiles["soak"].duration_seconds == 8 * 60 * 60


def test_explicit_cli_values_override_profile_values():
    args = parse_args(
        [
            "--profile",
            "peak",
            "--scenario",
            "server-info",
            "--users",
            "3",
            "--duration",
            "7s",
            "--ramp-up",
            "0s",
            "--rate",
            "0",
            "--seed",
            "9",
        ]
    )

    assert args.profile == "peak"
    assert args.scenario == "server-info"
    assert args.users == 3
    assert args.duration == 7
    assert args.arrival_pattern == "closed"
    assert args.rate == 0
    assert args.seed == 9


def test_rate_override_replaces_spike_shape():
    args = parse_args(["--profile", "spike", "--rate", "25"])

    assert args.arrival_pattern == "fixed"
    assert args.rate == 25
    assert args.stage_rates == ()
    assert args.spike_rate is None
    assert args.spike_start is None
    assert args.spike_duration is None


def test_action_weight_override_preserves_other_profile_weights():
    args = parse_args(["--profile", "peak", "--action-weight", "read=60"])

    assert args.action_weights == {
        "read": 60,
        "create": 25,
        "update": 15,
        "delete": 15,
    }


@pytest.mark.parametrize(
    ("replacement", "message"),
    [
        ("seed = 20260908\nunknown = 1", "unknown fields"),
        ('duration = "5s"', "positive number"),
        ("rate = 0", "closed arrival_pattern"),
    ],
)
def test_profile_loader_rejects_unknown_invalid_and_contradictory_values(
    tmp_path, replacement, message
):
    source = Path("tests/stress/profiles.toml").read_text(encoding="utf-8")
    if "unknown" in replacement:
        source = source.replace("seed = 20260908", replacement, 1)
    elif "duration" in replacement:
        source = source.replace('duration = "5s"', 'duration = "bad"', 1)
    else:
        source = source.replace(
            'arrival_pattern = "fixed"', 'arrival_pattern = "closed"', 1
        )
    profile_path = tmp_path / "profiles.toml"
    profile_path.write_text(source, encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        load_profiles(profile_path)


def test_remote_mutating_scenario_requires_explicit_performance_target():
    with pytest.raises(SystemExit):
        parse_args(
            [
                "--scenario",
                "mixed",
                "--host",
                "example.test",
                "--port",
                "443",
                "--target-id",
                "prod-like",
                "--target-environment",
                "staging",
            ]
        )


def test_normalized_parameters_do_not_contain_credentials(monkeypatch):
    monkeypatch.setenv("CFMS_LOAD_PASSWORD", "do-not-serialize")
    args = parse_args(
        [
            "--scenario",
            "auth-read",
            "--host",
            "example.test",
            "--port",
            "443",
            "--target-id",
            "perf-a",
            "--target-environment",
            "performance",
            "--username",
            "load-user",
        ]
    )

    result = normalized_parameters(args, account_pool_size=1)

    serialized = json.dumps(result)
    assert "do-not-serialize" not in serialized
    assert "load-user" not in serialized
    assert result["target_config_id"] == "perf-a"


def test_account_pool_loads_distinct_accounts_without_exposing_passwords(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("PERF_PASSWORD_A", "secret-a")
    monkeypatch.setenv("PERF_PASSWORD_B", "secret-b")
    account_path = tmp_path / "accounts.toml"
    account_path.write_text(
        """schema_version = 1
[[accounts]]
username = "perf-a"
password_env = "PERF_PASSWORD_A"
[[accounts]]
username = "perf-b"
password_env = "PERF_PASSWORD_B"
""",
        encoding="utf-8",
    )

    credentials = load_account_pool(account_path)

    assert [item.username for item in credentials] == ["perf-a", "perf-b"]
    assert "secret-a" not in repr(credentials)
    assert "secret-b" not in repr(credentials)


@pytest.mark.asyncio
async def test_expected_rate_rejection_is_separate_from_errors():
    stats = LoadStats()

    await timed_call(
        stats,
        "server_info",
        lambda: _response(
            429,
            {"scope": "ip", "limit": 12, "retry_after_seconds": 3},
        ),
        expected_rejection_codes={429},
    )

    result = summarize(stats, elapsed=1, scenario="request-rate-control", users=1)
    assert result["errors"] == {}
    assert result["expected_rejections"] == {"code_429:ip": 1}
    assert result["success_rate"] == 0
    assert result["valid_outcome_rate"] == 1


@pytest.mark.asyncio
async def test_invalid_rate_rejection_contract_is_an_error():
    stats = LoadStats()

    await timed_call(
        stats,
        "server_info",
        lambda: _response(429, {"scope": "ip"}),
        expected_rejection_codes={429},
    )

    result = summarize(stats, elapsed=1, scenario="request-rate-control", users=1)
    assert result["expected_rejections"] == {}
    assert result["errors"] == {"invalid_rejection_contract_429": 1}


async def _response(code, data):
    return {"code": code, "data": data}


def test_latency_histogram_has_bounded_storage_and_reports_percentiles():
    histogram = BoundedLatencyHistogram()
    for value in range(20_000):
        histogram.record(value / 10)

    summary = histogram.summary()

    assert histogram.retained_values <= 2048
    assert summary["p50"] == pytest.approx(1000, rel=0.02)
    assert summary["p99"] == pytest.approx(1980, rel=0.02)
    assert summary["max"] == pytest.approx(1999.9)


def test_connection_metrics_report_success_latency_and_peak():
    stats = ConnectionStats()
    stats.connected(12)
    stats.connected(20)
    stats.disconnected()

    result = stats.summary()

    assert result["success_rate"] == 1
    assert result["handshake_latency_ms"]["p95"] == 12
    assert result["current_connections"] == 1
    assert result["peak_connections"] == 2


def test_generator_rss_metric_reads_current_process_memory():
    assert current_rss_bytes() > 0


@pytest.mark.asyncio
async def test_generator_monitor_stops_without_waiting_for_sample_interval():
    stop_event = asyncio.Event()
    health = GeneratorHealth()
    task = asyncio.create_task(monitor_generator(stop_event, health, interval=1))
    started = time.perf_counter()

    stop_event.set()
    await task

    assert time.perf_counter() - started < 0.1


def test_step_profile_builds_one_phase_per_rate():
    args = parse_args(["--profile", "stress", "--duration", "8s", "--ramp-up", "0s"])

    phases = build_phases(args)

    assert [phase.rate for phase in phases] == list(args.stage_rates)
    assert sum(phase.duration_seconds for phase in phases) == 8


class _Frame:
    def __init__(self, data):
        self.data = data


class _Stream:
    def __init__(self, responses):
        self.responses = list(responses)
        self.sent = []

    async def send(self, data, frame_type=None):
        self.sent.append(data)

    async def recv(self):
        return self.responses.pop(0)


class _Multiplexer:
    def __init__(self, stream):
        self.stream = stream

    def open_stream(self):
        return self.stream


@pytest.mark.asyncio
async def test_upload_client_returns_resume_offset_and_sends_complete_chunks(tmp_path):
    source = tmp_path / "resume-upload.bin"
    source.write_bytes(b"x" * 100_000)
    stream = _Stream(
        [
            _Frame(
                orjson.dumps(
                    {
                        "action": "transfer_file",
                        "data": {
                            "file_size": 100_000,
                            "chunk_size": 65_536,
                            "offset": 0,
                        },
                    }
                )
            )
        ]
    )
    client = CFMSTestClient()
    client.multiplexer = _Multiplexer(stream)

    offset = await client.upload_file_to_server(
        "task", str(source), interrupt_after_bytes=50_000
    )

    assert offset == 65_536
    request = orjson.loads(stream.sent[0])
    assert request["data"]["file_size"] == 100_000
    assert len(stream.sent[1]) == 65_536


@pytest.mark.asyncio
async def test_download_client_returns_checkpoint_for_nonzero_resume():
    encoded = base64.b64encode(b"x").decode()
    stream = _Stream(
        [
            _Frame(
                orjson.dumps(
                    {
                        "action": "transfer_file",
                        "data": {"file_size": 131_072, "chunk_size": 65_536},
                    }
                )
            ),
            _Frame(
                orjson.dumps(
                    {
                        "action": "file_chunk",
                        "data": {
                            "index": 0,
                            "chunk": encoded,
                            "tag": encoded,
                            "prefix": encoded,
                        },
                    }
                )
            ),
        ]
    )
    client = CFMSTestClient()
    client.multiplexer = _Multiplexer(stream)

    checkpoint = await client.download_file_from_server(
        "task", "unused.bin", interrupt_after_bytes=65_536
    )

    assert checkpoint is not None
    assert checkpoint.offset == 65_536
    request = orjson.loads(stream.sent[0])
    assert request["data"]["offset"] == 0
    assert stream.sent[1] == b"ready"
