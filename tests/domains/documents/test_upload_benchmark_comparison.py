import pytest

from tests.stress.ws_load import write_unique_payload
from tools.compare_upload_benchmarks import compare_results


def _result(scenario, throughput, p95, *, success_rate=1.0):
    return {
        "scenario": scenario,
        "throughput_rps": throughput,
        "success_rate": success_rate,
        "latency_ms": {"p95": p95},
        "parameters": {
            "duration_seconds": 30,
            "ramp_up_seconds": 0,
            "rate": 0,
            "payload_size_bytes": 262144,
        },
    }


def test_unique_upload_payloads_have_stable_size_and_distinct_content(tmp_path):
    first = tmp_path / "first.bin"
    second = tmp_path / "second.bin"

    write_unique_payload(first, 100, worker_id=1, sequence=1)
    write_unique_payload(second, 100, worker_id=1, sequence=2)

    assert first.stat().st_size == 100
    assert second.stat().st_size == 100
    assert first.read_bytes() != second.read_bytes()


def test_upload_benchmark_comparison_accepts_changes_within_threshold():
    comparisons, failures = compare_results(
        [
            _result("upload-unique", 100, 20),
            _result("upload-unique", 102, 22),
        ],
        [
            _result("upload-unique", 96, 21),
            _result("upload-unique", 98, 22),
        ],
        max_regression=0.10,
        minimum_success_rate=1.0,
    )

    assert failures == []
    assert comparisons[0]["scenario"] == "upload-unique"


def test_upload_benchmark_comparison_rejects_unique_upload_regressions():
    _comparisons, failures = compare_results(
        [_result("upload-unique", 100, 20)],
        [_result("upload-unique", 80, 25, success_rate=0.99)],
        max_regression=0.10,
        minimum_success_rate=1.0,
    )

    assert failures == [
        "upload-unique: success rate 99.00% is below 100.00%",
        "upload-unique: throughput regressed by 20.00%",
        "upload-unique: p95 regressed by 25.00%",
    ]


def test_upload_benchmark_comparison_requires_matching_scenarios():
    with pytest.raises(ValueError, match="scenarios do not match"):
        compare_results(
            [_result("upload-unique", 100, 20)],
            [
                _result("upload-unique", 100, 20),
                _result("upload-duplicate", 100, 20),
            ],
            max_regression=0.10,
            minimum_success_rate=1.0,
        )
