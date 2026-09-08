import argparse
import json
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from statistics import median

FILE_SCENARIOS = {
    "download",
    "download-resume",
    "upload-duplicate",
    "upload-resume",
    "upload-unique",
}


@dataclass(frozen=True)
class ComparisonThresholds:
    max_throughput_regression: float = 0.10
    max_latency_regression: float = 0.10
    minimum_success_rate: float = 1.0
    max_dropped_increase: float = 0
    minimum_throughput_rps: float | None = None
    maximum_p95_ms: float | None = None
    maximum_p99_ms: float | None = None
    minimum_file_bytes_per_second: float | None = None


def load_results(path: Path) -> list[dict]:
    paths = [path] if path.is_file() else sorted(path.glob("*.json"))
    results = []
    for result_path in paths:
        result = json.loads(result_path.read_text(encoding="utf-8-sig"))
        if isinstance(result, dict) and isinstance(result.get("scenario"), str):
            results.append(result)
    if not results:
        raise ValueError(f"No benchmark result JSON files found in {path}")
    return results


def _required_number(result: dict, *path: str) -> float:
    value: object = result
    for part in path:
        if not isinstance(value, dict) or part not in value:
            raise ValueError(
                f"{result.get('scenario', 'unknown')} result is missing metric "
                f"{'.'.join(path)}"
            )
        value = value[part]
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValueError(
            f"{result.get('scenario', 'unknown')} metric {'.'.join(path)} "
            "must be numeric"
        )
    return float(value)


def _harness_commit(result: dict) -> str:
    harness = result.get("harness")
    commit = harness.get("commit") if isinstance(harness, dict) else None
    if not isinstance(commit, str) or not commit:
        scenario = result.get("scenario", "unknown")
        raise ValueError(
            f"{scenario} result is missing harness.commit; legacy results must be "
            "rerun or annotated with the verified harness commit"
        )
    return commit


def _comparison_parameters(result: dict) -> tuple[str, int | None]:
    parameters = result.get("parameters")
    if not isinstance(parameters, dict):
        raise ValueError(f"{result.get('scenario')} result is missing parameters")
    normalized = dict(parameters)
    seed = normalized.pop("random_seed", normalized.pop("seed", None))
    return json.dumps(normalized, sort_keys=True, separators=(",", ":")), seed


def _validate_group(scenario: str, baseline: list[dict], candidate: list[dict]) -> None:
    if len(baseline) != len(candidate):
        raise ValueError(f"{scenario} baseline and candidate run counts do not match")
    commits = {_harness_commit(result) for result in [*baseline, *candidate]}
    if len(commits) != 1:
        raise ValueError(f"{scenario} harness commits do not match")

    baseline_parameters = [_comparison_parameters(result) for result in baseline]
    candidate_parameters = [_comparison_parameters(result) for result in candidate]
    parameter_signatures = {
        signature for signature, _seed in [*baseline_parameters, *candidate_parameters]
    }
    if len(parameter_signatures) != 1:
        raise ValueError(f"{scenario} benchmark parameters do not match")
    baseline_seeds = sorted(seed for _signature, seed in baseline_parameters)
    candidate_seeds = sorted(seed for _signature, seed in candidate_parameters)
    if baseline_seeds != candidate_seeds:
        raise ValueError(f"{scenario} random seed sets do not match")


def _optional_file_throughput(results: list[dict]) -> list[float] | None:
    present = ["bytes_per_second" in result for result in results]
    if not any(present):
        return None
    if not all(present):
        raise ValueError("file throughput is missing from one or more results")
    return [_required_number(result, "bytes_per_second") for result in results]


def _relative_change(candidate: float, baseline: float, *, metric: str) -> float:
    if baseline <= 0:
        raise ValueError(f"baseline {metric} must be positive")
    return candidate / baseline - 1


def compare_results(
    baseline_results: list[dict],
    candidate_results: list[dict],
    *,
    max_regression: float | None = None,
    minimum_success_rate: float = 1.0,
    max_throughput_regression: float | None = None,
    max_latency_regression: float | None = None,
    max_dropped_increase: float = 0,
    minimum_throughput_rps: float | None = None,
    maximum_p95_ms: float | None = None,
    maximum_p99_ms: float | None = None,
    minimum_file_bytes_per_second: float | None = None,
) -> tuple[list[dict], list[str]]:
    if max_regression is not None:
        if max_throughput_regression is None:
            max_throughput_regression = max_regression
        if max_latency_regression is None:
            max_latency_regression = max_regression
    throughput_threshold = (
        0.10 if max_throughput_regression is None else max_throughput_regression
    )
    latency_threshold = (
        0.10 if max_latency_regression is None else max_latency_regression
    )

    grouped_baseline: dict[str, list[dict]] = defaultdict(list)
    grouped_candidate: dict[str, list[dict]] = defaultdict(list)
    for result in baseline_results:
        grouped_baseline[result["scenario"]].append(result)
    for result in candidate_results:
        grouped_candidate[result["scenario"]].append(result)
    if grouped_baseline.keys() != grouped_candidate.keys():
        raise ValueError("Baseline and candidate scenarios do not match")

    comparisons = []
    failures = []
    for scenario in sorted(grouped_baseline):
        baseline = grouped_baseline[scenario]
        candidate = grouped_candidate[scenario]
        _validate_group(scenario, baseline, candidate)

        baseline_throughput = median(
            _required_number(row, "throughput_rps") for row in baseline
        )
        candidate_throughput = median(
            _required_number(row, "throughput_rps") for row in candidate
        )
        baseline_p95 = median(
            _required_number(row, "latency_ms", "p95") for row in baseline
        )
        candidate_p95 = median(
            _required_number(row, "latency_ms", "p95") for row in candidate
        )
        baseline_p99 = median(
            _required_number(row, "latency_ms", "p99") for row in baseline
        )
        candidate_p99 = median(
            _required_number(row, "latency_ms", "p99") for row in candidate
        )
        baseline_success = median(
            _required_number(row, "success_rate") for row in baseline
        )
        candidate_success = median(
            _required_number(row, "success_rate") for row in candidate
        )
        baseline_dropped = median(
            _required_number(row, "dropped_iterations") for row in baseline
        )
        candidate_dropped = median(
            _required_number(row, "dropped_iterations") for row in candidate
        )

        throughput_change = _relative_change(
            candidate_throughput, baseline_throughput, metric="throughput"
        )
        p95_change = _relative_change(candidate_p95, baseline_p95, metric="p95")
        p99_change = _relative_change(candidate_p99, baseline_p99, metric="p99")
        file_comparison = None
        baseline_file_values = (
            _optional_file_throughput(baseline) if scenario in FILE_SCENARIOS else None
        )
        candidate_file_values = (
            _optional_file_throughput(candidate) if scenario in FILE_SCENARIOS else None
        )
        if (baseline_file_values is None) != (candidate_file_values is None):
            raise ValueError(f"{scenario} file throughput availability does not match")
        if baseline_file_values is not None and candidate_file_values is not None:
            baseline_file = median(baseline_file_values)
            candidate_file = median(candidate_file_values)
            file_comparison = {
                "baseline_bytes_per_second": baseline_file,
                "candidate_bytes_per_second": candidate_file,
                "change": _relative_change(
                    candidate_file, baseline_file, metric="file throughput"
                ),
            }

        comparison = {
            "scenario": scenario,
            "harness_commit": _harness_commit(baseline[0]),
            "baseline_runs": len(baseline),
            "candidate_runs": len(candidate),
            "throughput_rps": {
                "baseline_median": baseline_throughput,
                "candidate_median": candidate_throughput,
                "change": throughput_change,
            },
            "latency_ms": {
                "p95": {
                    "baseline_median": baseline_p95,
                    "candidate_median": candidate_p95,
                    "change": p95_change,
                },
                "p99": {
                    "baseline_median": baseline_p99,
                    "candidate_median": candidate_p99,
                    "change": p99_change,
                },
            },
            "success_rate": {
                "baseline_median": baseline_success,
                "candidate_median": candidate_success,
                "change": candidate_success - baseline_success,
            },
            "dropped_iterations": {
                "baseline_median": baseline_dropped,
                "candidate_median": candidate_dropped,
                "change": candidate_dropped - baseline_dropped,
            },
            "file_throughput": file_comparison,
        }
        comparisons.append(comparison)

        if candidate_success < minimum_success_rate:
            failures.append(
                f"{scenario}: candidate success rate {candidate_success:.2%} is below "
                f"{minimum_success_rate:.2%}"
            )
        if throughput_change < -throughput_threshold:
            failures.append(
                f"{scenario}: throughput regressed by {-throughput_change:.2%}"
            )
        if p95_change > latency_threshold:
            failures.append(f"{scenario}: p95 regressed by {p95_change:.2%}")
        if p99_change > latency_threshold:
            failures.append(f"{scenario}: p99 regressed by {p99_change:.2%}")
        if candidate_dropped - baseline_dropped > max_dropped_increase:
            failures.append(
                f"{scenario}: dropped iterations increased by "
                f"{candidate_dropped - baseline_dropped:g}"
            )
        if file_comparison is not None and (
            file_comparison["change"] < -throughput_threshold
        ):
            failures.append(
                f"{scenario}: file throughput regressed by "
                f"{-file_comparison['change']:.2%}"
            )

        for value, limit, label, comparison_operator in (
            (
                candidate_throughput,
                minimum_throughput_rps,
                "throughput",
                "minimum",
            ),
            (candidate_p95, maximum_p95_ms, "p95", "maximum"),
            (candidate_p99, maximum_p99_ms, "p99", "maximum"),
        ):
            if limit is None:
                continue
            failed = (
                value < limit if comparison_operator == "minimum" else value > limit
            )
            if failed:
                failures.append(
                    f"{scenario}: candidate {label} {value:g} violates "
                    f"{comparison_operator} SLO {limit:g}"
                )
        if minimum_file_bytes_per_second is not None:
            if file_comparison is None:
                if scenario in FILE_SCENARIOS:
                    failures.append(
                        f"{scenario}: file throughput is required by the absolute SLO"
                    )
            elif (
                file_comparison["candidate_bytes_per_second"]
                < minimum_file_bytes_per_second
            ):
                failures.append(
                    f"{scenario}: candidate file throughput "
                    f"{file_comparison['candidate_bytes_per_second']:g} violates "
                    f"minimum SLO {minimum_file_bytes_per_second:g}"
                )
    return comparisons, failures


def _fraction(value: str) -> float:
    number = float(value)
    if not 0 <= number < 1:
        raise argparse.ArgumentTypeError("value must be between 0 and 1")
    return number


def _success_rate(value: str) -> float:
    number = float(value)
    if not 0 < number <= 1:
        raise argparse.ArgumentTypeError("value must be greater than 0 and at most 1")
    return number


def _non_negative(value: str) -> float:
    number = float(value)
    if number < 0:
        raise argparse.ArgumentTypeError("value must be non-negative")
    return number


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare repeated CFMS performance results"
    )
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument(
        "--max-regression",
        type=_fraction,
        help="Compatibility alias setting both throughput and latency thresholds",
    )
    parser.add_argument("--max-throughput-regression", type=_fraction, default=0.10)
    parser.add_argument("--max-latency-regression", type=_fraction, default=0.10)
    parser.add_argument("--minimum-success-rate", type=_success_rate, default=1.0)
    parser.add_argument("--max-dropped-increase", type=_non_negative, default=0)
    parser.add_argument("--minimum-throughput-rps", type=_non_negative)
    parser.add_argument("--maximum-p95-ms", type=_non_negative)
    parser.add_argument("--maximum-p99-ms", type=_non_negative)
    parser.add_argument("--minimum-file-bytes-per-second", type=_non_negative)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if args.max_regression is not None:
        args.max_throughput_regression = args.max_regression
        args.max_latency_regression = args.max_regression
    return args


def _write_report(path: Path, report: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    thresholds = ComparisonThresholds(
        max_throughput_regression=args.max_throughput_regression,
        max_latency_regression=args.max_latency_regression,
        minimum_success_rate=args.minimum_success_rate,
        max_dropped_increase=args.max_dropped_increase,
        minimum_throughput_rps=args.minimum_throughput_rps,
        maximum_p95_ms=args.maximum_p95_ms,
        maximum_p99_ms=args.maximum_p99_ms,
        minimum_file_bytes_per_second=args.minimum_file_bytes_per_second,
    )
    try:
        comparisons, failures = compare_results(
            load_results(args.baseline),
            load_results(args.candidate),
            **asdict(thresholds),
        )
        report = {
            "schema_version": 1,
            "passed": not failures,
            "thresholds": asdict(thresholds),
            "comparisons": comparisons,
            "failures": failures,
        }
        exit_code = 1 if failures else 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        report = {
            "schema_version": 1,
            "passed": False,
            "configuration_error": str(exc),
            "comparisons": [],
            "failures": [],
        }
        exit_code = 2
    if args.output is not None:
        _write_report(args.output, report)
    print(json.dumps(report, indent=2))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
