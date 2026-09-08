import json

import pytest

from tests.stress.ws_load import write_unique_payload
from tools.compare_upload_benchmarks import compare_results, main


def _result(
    scenario,
    throughput,
    p95,
    *,
    p99=None,
    success_rate=1.0,
    dropped=0,
    seed=1,
    harness_commit="harness-a",
    file_throughput=None,
    users=8,
):
    result = {
        "scenario": scenario,
        "throughput_rps": throughput,
        "success_rate": success_rate,
        "dropped_iterations": dropped,
        "latency_ms": {"p95": p95, "p99": p95 if p99 is None else p99},
        "parameters": {
            "duration_seconds": 30,
            "ramp_up_seconds": 0,
            "rate": 0,
            "payload_size_bytes": 262144,
            "random_seed": seed,
            "users": users,
        },
        "harness": {"commit": harness_commit},
    }
    if file_throughput is not None:
        result["bytes_per_second"] = file_throughput
    return result


def test_unique_upload_payloads_have_stable_size_and_distinct_content(tmp_path):
    first = tmp_path / "first.bin"
    second = tmp_path / "second.bin"

    write_unique_payload(first, 100, worker_id=1, sequence=1)
    write_unique_payload(second, 100, worker_id=1, sequence=2)

    assert first.stat().st_size == 100
    assert second.stat().st_size == 100
    assert first.read_bytes() != second.read_bytes()


def test_comparison_uses_medians_and_accepts_changes_within_threshold():
    comparisons, failures = compare_results(
        [
            _result("server-info", 50, 40, seed=1),
            _result("server-info", 100, 20, seed=2),
            _result("server-info", 102, 22, seed=3),
        ],
        [
            _result("server-info", 200, 80, seed=1),
            _result("server-info", 96, 21, seed=2),
            _result("server-info", 98, 22, seed=3),
        ],
        max_regression=0.10,
        minimum_success_rate=1.0,
    )

    assert failures == []
    comparison = comparisons[0]
    assert comparison["scenario"] == "server-info"
    assert comparison["throughput_rps"]["baseline_median"] == 100
    assert comparison["throughput_rps"]["candidate_median"] == 98
    assert comparison["latency_ms"]["p95"]["candidate_median"] == 22


def test_non_file_scenario_ignores_zero_transfer_rate_field():
    baseline = _result("server-info", 100, 20, file_throughput=0)
    candidate = _result("server-info", 100, 20, file_throughput=0)

    comparisons, failures = compare_results([baseline], [candidate])

    assert failures == []
    assert comparisons[0]["file_throughput"] is None


def test_comparison_rejects_low_success_and_latency_throughput_regressions():
    _comparisons, failures = compare_results(
        [_result("upload-unique", 100, 20, p99=30)],
        [
            _result(
                "upload-unique",
                80,
                25,
                p99=39,
                success_rate=0.99,
            )
        ],
        max_regression=0.10,
        minimum_success_rate=1.0,
    )

    assert failures == [
        "upload-unique: candidate success rate 99.00% is below 100.00%",
        "upload-unique: throughput regressed by 20.00%",
        "upload-unique: p95 regressed by 25.00%",
        "upload-unique: p99 regressed by 30.00%",
    ]


def test_comparison_requires_matching_scenarios():
    with pytest.raises(ValueError, match="scenarios do not match"):
        compare_results(
            [_result("upload-unique", 100, 20)],
            [
                _result("upload-unique", 100, 20),
                _result("upload-duplicate", 100, 20),
            ],
            max_regression=0.10,
        )


def test_comparison_rejects_harness_commit_mismatch():
    with pytest.raises(ValueError, match="harness commits do not match"):
        compare_results(
            [_result("mixed", 100, 20, harness_commit="one")],
            [_result("mixed", 100, 20, harness_commit="two")],
        )


def test_comparison_gives_migration_error_for_legacy_result_without_commit():
    baseline = _result("upload-unique", 100, 20)
    candidate = _result("upload-unique", 100, 20)
    baseline.pop("harness")

    with pytest.raises(ValueError, match="legacy results must be rerun"):
        compare_results([baseline], [candidate])


def test_comparison_rejects_parameter_mismatch():
    with pytest.raises(ValueError, match="parameters do not match"):
        compare_results(
            [_result("mixed", 100, 20, users=8)],
            [_result("mixed", 100, 20, users=9)],
        )


def test_comparison_rejects_random_seed_set_mismatch():
    with pytest.raises(ValueError, match="random seed sets do not match"):
        compare_results(
            [_result("mixed", 100, 20, seed=1)],
            [_result("mixed", 100, 20, seed=2)],
        )


def test_comparison_rejects_missing_metrics():
    candidate = _result("mixed", 100, 20)
    candidate["latency_ms"].pop("p99")

    with pytest.raises(ValueError, match="missing metric latency_ms.p99"):
        compare_results([_result("mixed", 100, 20)], [candidate])


def test_comparison_checks_dropped_iterations_and_file_throughput():
    comparisons, failures = compare_results(
        [
            _result(
                "download",
                10,
                20,
                dropped=0,
                file_throughput=1_000_000,
            )
        ],
        [
            _result(
                "download",
                10,
                20,
                dropped=3,
                file_throughput=700_000,
            )
        ],
        max_regression=0.10,
    )

    assert comparisons[0]["file_throughput"]["change"] == pytest.approx(-0.3)
    assert failures == [
        "download: dropped iterations increased by 3",
        "download: file throughput regressed by 30.00%",
    ]


def test_comparison_applies_absolute_slos():
    _comparisons, failures = compare_results(
        [_result("download", 100, 20, p99=30, file_throughput=1_000)],
        [_result("download", 90, 25, p99=35, file_throughput=900)],
        max_regression=0.50,
        minimum_throughput_rps=95,
        maximum_p95_ms=22,
        maximum_p99_ms=32,
        minimum_file_bytes_per_second=950,
    )

    assert failures == [
        "download: candidate throughput 90 violates minimum SLO 95",
        "download: candidate p95 25 violates maximum SLO 22",
        "download: candidate p99 35 violates maximum SLO 32",
        "download: candidate file throughput 900 violates minimum SLO 950",
    ]


def test_cli_outputs_machine_readable_failure_and_exit_code(tmp_path, capsys):
    baseline = tmp_path / "baseline"
    candidate = tmp_path / "candidate"
    baseline.mkdir()
    candidate.mkdir()
    (baseline / "run.json").write_text(
        json.dumps(_result("server-info", 100, 20)), encoding="utf-8"
    )
    (candidate / "run.json").write_text(
        json.dumps(_result("server-info", 70, 20)), encoding="utf-8"
    )

    exit_code = main([str(baseline), str(candidate), "--max-regression", "0.1"])
    output = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert output["passed"] is False
    assert output["failures"] == ["server-info: throughput regressed by 30.00%"]
