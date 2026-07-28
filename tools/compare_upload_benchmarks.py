import argparse
import json
from collections import defaultdict
from pathlib import Path
from statistics import median


def load_results(directory: Path) -> list[dict]:
    results = []
    for path in sorted(directory.glob("*.json")):
        result = json.loads(path.read_text(encoding="utf-8-sig"))
        scenario = result.get("scenario")
        if scenario not in {"upload-unique", "upload-duplicate"}:
            continue
        results.append(result)
    if not results:
        raise ValueError(f"No upload benchmark JSON files found in {directory}")
    return results


def compare_results(
    baseline_results: list[dict],
    candidate_results: list[dict],
    *,
    max_regression: float,
    minimum_success_rate: float,
) -> tuple[list[dict], list[str]]:
    grouped_baseline = defaultdict(list)
    grouped_candidate = defaultdict(list)
    for result in baseline_results:
        grouped_baseline[result["scenario"]].append(result)
    for result in candidate_results:
        grouped_candidate[result["scenario"]].append(result)

    if grouped_baseline.keys() != grouped_candidate.keys():
        raise ValueError("Baseline and candidate scenarios do not match")
    common_scenarios = sorted(grouped_baseline)
    if "upload-unique" not in common_scenarios:
        raise ValueError("Both result sets must include upload-unique")

    comparisons = []
    failures = []
    for scenario in common_scenarios:
        baseline = grouped_baseline[scenario]
        candidate = grouped_candidate[scenario]
        baseline_parameters = {
            json.dumps(row["parameters"], sort_keys=True) for row in baseline
        }
        candidate_parameters = {
            json.dumps(row["parameters"], sort_keys=True) for row in candidate
        }
        if len(baseline_parameters | candidate_parameters) != 1:
            raise ValueError(f"{scenario} benchmark parameters do not match")

        baseline_throughput = median(row["throughput_rps"] for row in baseline)
        candidate_throughput = median(row["throughput_rps"] for row in candidate)
        baseline_p95 = median(row["latency_ms"]["p95"] for row in baseline)
        candidate_p95 = median(row["latency_ms"]["p95"] for row in candidate)
        if baseline_throughput <= 0 or baseline_p95 <= 0:
            raise ValueError(f"{scenario} baseline metrics must be positive")

        throughput_change = candidate_throughput / baseline_throughput - 1
        p95_change = candidate_p95 / baseline_p95 - 1
        success_rate = min(row["success_rate"] for row in [*baseline, *candidate])
        comparison = {
            "scenario": scenario,
            "baseline_runs": len(baseline),
            "candidate_runs": len(candidate),
            "baseline_throughput_rps": baseline_throughput,
            "candidate_throughput_rps": candidate_throughput,
            "throughput_change": throughput_change,
            "baseline_p95_ms": baseline_p95,
            "candidate_p95_ms": candidate_p95,
            "p95_change": p95_change,
            "minimum_success_rate": success_rate,
        }
        comparisons.append(comparison)

        if success_rate < minimum_success_rate:
            failures.append(
                f"{scenario}: success rate {success_rate:.2%} is below "
                f"{minimum_success_rate:.2%}"
            )
        if throughput_change < -max_regression:
            failures.append(
                f"{scenario}: throughput regressed by {-throughput_change:.2%}"
            )
        if p95_change > max_regression:
            failures.append(f"{scenario}: p95 regressed by {p95_change:.2%}")

    return comparisons, failures


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare repeated CFMS upload benchmark results"
    )
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--max-regression", type=float, default=0.10)
    parser.add_argument("--minimum-success-rate", type=float, default=1.0)
    args = parser.parse_args()
    if not 0 <= args.max_regression < 1:
        parser.error("--max-regression must be between 0 and 1")
    if not 0 < args.minimum_success_rate <= 1:
        parser.error("--minimum-success-rate must be between 0 and 1")
    return args


def main() -> int:
    args = parse_args()
    comparisons, failures = compare_results(
        load_results(args.baseline),
        load_results(args.candidate),
        max_regression=args.max_regression,
        minimum_success_rate=args.minimum_success_rate,
    )
    print(json.dumps({"comparisons": comparisons, "failures": failures}, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
