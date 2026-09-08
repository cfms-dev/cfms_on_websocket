import argparse
import math
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

DEFAULT_PROFILE_PATH = Path(__file__).with_name("profiles.toml")
REQUIRED_PROFILES = {"smoke", "peak", "stress", "spike", "soak"}
SCENARIOS = {
    "admission-control",
    "auth-read",
    "connection-storm",
    "download",
    "download-resume",
    "mixed",
    "multiplex",
    "reconnect-storm",
    "request-rate-control",
    "server-info",
    "upload-duplicate",
    "upload-resume",
    "upload-unique",
}
AUTHENTICATED_SCENARIOS = SCENARIOS - {
    "admission-control",
    "connection-storm",
    "reconnect-storm",
    "request-rate-control",
    "server-info",
}
MUTATING_SCENARIOS = {
    "download",
    "download-resume",
    "mixed",
    "upload-duplicate",
    "upload-resume",
    "upload-unique",
}
MIXED_ACTIONS = {"read", "create", "update", "delete"}
ARRIVAL_PATTERNS = {"closed", "fixed", "step", "spike"}
PROFILE_FIELDS = {
    "action_weights",
    "arrival_pattern",
    "duration",
    "inflight_per_user",
    "payload_size",
    "ramp_up",
    "rate",
    "scenario",
    "seed",
    "spike_duration",
    "spike_rate",
    "spike_start",
    "stage_rates",
    "users",
}
_DURATION_PATTERN = re.compile(r"(?P<value>(?:\d+(?:\.\d*)?|\.\d+))(?P<unit>ms|s|m|h)")
_DURATION_MULTIPLIERS = {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0}


@dataclass(frozen=True)
class LoadProfile:
    name: str
    scenario: str
    users: int
    duration_seconds: float
    ramp_up_seconds: float
    arrival_pattern: str
    rate: float
    stage_rates: tuple[float, ...]
    spike_rate: float | None
    spike_start_seconds: float | None
    spike_duration_seconds: float | None
    inflight_per_user: int
    payload_size_bytes: int
    seed: int
    action_weights: dict[str, float]

    def as_defaults(self) -> dict[str, object]:
        return {
            "scenario": self.scenario,
            "users": self.users,
            "duration": self.duration_seconds,
            "ramp_up": self.ramp_up_seconds,
            "arrival_pattern": self.arrival_pattern,
            "rate": self.rate,
            "stage_rates": self.stage_rates,
            "spike_rate": self.spike_rate,
            "spike_start": self.spike_start_seconds,
            "spike_duration": self.spike_duration_seconds,
            "inflight_per_user": self.inflight_per_user,
            "payload_size": self.payload_size_bytes,
            "seed": self.seed,
            "action_weights": dict(self.action_weights),
        }


def parse_duration(value: object, *, field_name: str = "duration") -> float:
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be a positive duration")
    if isinstance(value, int | float):
        seconds = float(value)
    elif isinstance(value, str):
        match = _DURATION_PATTERN.fullmatch(value.strip())
        if match is None:
            raise ValueError(
                f"{field_name} must be a positive number of seconds or use ms/s/m/h"
            )
        seconds = (
            float(match.group("value")) * _DURATION_MULTIPLIERS[match.group("unit")]
        )
    else:
        raise ValueError(f"{field_name} must be a positive duration")
    if not math.isfinite(seconds) or seconds <= 0:
        raise ValueError(f"{field_name} must be a positive duration")
    return seconds


def _non_negative_duration(value: object, *, field_name: str) -> float:
    if value in (0, 0.0, "0", "0s", "0ms"):
        return 0.0
    return parse_duration(value, field_name=field_name)


def _strict_number(value: object, *, field_name: str, minimum: float = 0) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValueError(f"{field_name} must be a number")
    number = float(value)
    if not math.isfinite(number) or number < minimum:
        raise ValueError(f"{field_name} must be at least {minimum:g}")
    return number


def _strict_positive_int(value: object, *, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{field_name} must be a positive integer")
    return value


def _validate_action_weights(
    raw: object, *, profile_name: str, scenario: str
) -> dict[str, float]:
    if raw is None:
        return {"read": 45.0, "create": 25.0, "update": 15.0, "delete": 15.0}
    if not isinstance(raw, dict):
        raise ValueError(f"profile {profile_name!r} action_weights must be a table")
    unknown = set(raw) - MIXED_ACTIONS
    if unknown:
        raise ValueError(
            f"profile {profile_name!r} has unknown action weights: {sorted(unknown)}"
        )
    weights = {
        action: _strict_number(value, field_name=f"action_weights.{action}")
        for action, value in raw.items()
    }
    if scenario != "mixed" and raw:
        raise ValueError("action_weights may only be configured for the mixed scenario")
    if scenario == "mixed" and sum(weights.values()) <= 0:
        raise ValueError("mixed action_weights must contain a positive total weight")
    return weights


def _profile_from_table(name: str, raw: object) -> LoadProfile:
    if not isinstance(raw, dict):
        raise ValueError(f"profile {name!r} must be a table")
    unknown = set(raw) - PROFILE_FIELDS
    if unknown:
        raise ValueError(f"profile {name!r} has unknown fields: {sorted(unknown)}")

    required = {
        "scenario",
        "users",
        "duration",
        "ramp_up",
        "arrival_pattern",
        "rate",
        "inflight_per_user",
        "payload_size",
        "seed",
    }
    missing = required - set(raw)
    if missing:
        raise ValueError(f"profile {name!r} is missing fields: {sorted(missing)}")

    scenario = raw["scenario"]
    if not isinstance(scenario, str) or scenario not in SCENARIOS:
        raise ValueError(f"profile {name!r} has unknown scenario: {scenario!r}")
    arrival_pattern = raw["arrival_pattern"]
    if not isinstance(arrival_pattern, str) or arrival_pattern not in ARRIVAL_PATTERNS:
        raise ValueError(
            f"profile {name!r} has unknown arrival_pattern: {arrival_pattern!r}"
        )

    duration = parse_duration(raw["duration"], field_name="duration")
    ramp_up = _non_negative_duration(raw["ramp_up"], field_name="ramp_up")
    rate = _strict_number(raw["rate"], field_name="rate")
    if ramp_up >= duration:
        raise ValueError("ramp_up must be less than duration")

    stage_rates_raw = raw.get("stage_rates", [])
    if not isinstance(stage_rates_raw, list):
        raise ValueError("stage_rates must be an array")
    stage_rates = tuple(
        _strict_number(value, field_name="stage_rates", minimum=0.0000001)
        for value in stage_rates_raw
    )
    spike_rate_raw = raw.get("spike_rate")
    spike_rate = (
        None
        if spike_rate_raw is None
        else _strict_number(spike_rate_raw, field_name="spike_rate", minimum=0.0000001)
    )
    spike_start = (
        None
        if raw.get("spike_start") is None
        else _non_negative_duration(raw["spike_start"], field_name="spike_start")
    )
    spike_duration = (
        None
        if raw.get("spike_duration") is None
        else parse_duration(raw["spike_duration"], field_name="spike_duration")
    )

    if arrival_pattern == "closed":
        if (
            rate != 0
            or stage_rates
            or any(
                value is not None for value in (spike_rate, spike_start, spike_duration)
            )
        ):
            raise ValueError(
                "closed arrival_pattern cannot define rate stages or a spike"
            )
    elif arrival_pattern == "fixed":
        if (
            rate <= 0
            or stage_rates
            or any(
                value is not None for value in (spike_rate, spike_start, spike_duration)
            )
        ):
            raise ValueError(
                "fixed arrival_pattern requires rate and no stages or spike"
            )
    elif arrival_pattern == "step":
        if (
            rate != 0
            or not stage_rates
            or any(
                value is not None for value in (spike_rate, spike_start, spike_duration)
            )
        ):
            raise ValueError(
                "step arrival_pattern requires stage_rates and cannot define rate or spike"
            )
        if tuple(sorted(stage_rates)) != stage_rates or len(set(stage_rates)) != len(
            stage_rates
        ):
            raise ValueError("stage_rates must be strictly increasing")
    elif (
        rate <= 0
        or spike_rate is None
        or spike_rate <= rate
        or spike_start is None
        or spike_duration is None
        or stage_rates
        or spike_start + spike_duration > duration
    ):
        raise ValueError(
            "spike arrival_pattern requires a higher spike_rate and an in-range spike window"
        )

    payload_size = _strict_positive_int(raw["payload_size"], field_name="payload_size")
    if scenario == "upload-unique" and payload_size < 32:
        raise ValueError("upload-unique requires payload_size of at least 32 bytes")
    seed = raw["seed"]
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("seed must be an integer")

    return LoadProfile(
        name=name,
        scenario=scenario,
        users=_strict_positive_int(raw["users"], field_name="users"),
        duration_seconds=duration,
        ramp_up_seconds=ramp_up,
        arrival_pattern=arrival_pattern,
        rate=rate,
        stage_rates=stage_rates,
        spike_rate=spike_rate,
        spike_start_seconds=spike_start,
        spike_duration_seconds=spike_duration,
        inflight_per_user=_strict_positive_int(
            raw["inflight_per_user"], field_name="inflight_per_user"
        ),
        payload_size_bytes=payload_size,
        seed=seed,
        action_weights=_validate_action_weights(
            raw.get("action_weights"), profile_name=name, scenario=scenario
        ),
    )


def load_profiles(path: Path = DEFAULT_PROFILE_PATH) -> dict[str, LoadProfile]:
    try:
        with path.open("rb") as profile_file:
            document = tomllib.load(profile_file)
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"Invalid profile TOML in {path}: {exc}") from exc
    unknown_root = set(document) - {"schema_version", "profiles"}
    if unknown_root:
        raise ValueError(f"Unknown profile document fields: {sorted(unknown_root)}")
    if document.get("schema_version") != 1:
        raise ValueError("profiles.toml schema_version must be 1")
    raw_profiles = document.get("profiles")
    if not isinstance(raw_profiles, dict):
        raise ValueError("profiles.toml must contain a profiles table")
    missing = REQUIRED_PROFILES - set(raw_profiles)
    if missing:
        raise ValueError(
            f"profiles.toml is missing required profiles: {sorted(missing)}"
        )
    return {name: _profile_from_table(name, raw) for name, raw in raw_profiles.items()}


def parse_stage_rates(value: str) -> tuple[float, ...]:
    try:
        rates = tuple(float(item.strip()) for item in value.split(",") if item.strip())
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "stage rates must be comma-separated numbers"
        ) from exc
    if not rates or any(not math.isfinite(rate) or rate <= 0 for rate in rates):
        raise argparse.ArgumentTypeError("stage rates must be positive numbers")
    return rates


def parse_action_weight(value: str) -> tuple[str, float]:
    action, separator, raw_weight = value.partition("=")
    if not separator or action not in MIXED_ACTIONS:
        raise argparse.ArgumentTypeError(
            "action weight must be read/create/update/delete=<non-negative number>"
        )
    try:
        weight = float(raw_weight)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("action weight must be numeric") from exc
    if not math.isfinite(weight) or weight < 0:
        raise argparse.ArgumentTypeError("action weight must be non-negative")
    return action, weight


def apply_profile_overrides(
    profile: LoadProfile, overrides: argparse.Namespace
) -> argparse.Namespace:
    values = profile.as_defaults()
    pattern_override = getattr(overrides, "arrival_pattern", None)
    if pattern_override is not None:
        values["arrival_pattern"] = pattern_override
        if pattern_override in {"closed", "fixed"}:
            values["stage_rates"] = ()
            values["spike_rate"] = None
            values["spike_start"] = None
            values["spike_duration"] = None
        elif pattern_override == "step":
            values["rate"] = 0.0
            values["spike_rate"] = None
            values["spike_start"] = None
            values["spike_duration"] = None
        else:
            values["stage_rates"] = ()
    for field_name in values:
        override = getattr(overrides, field_name, None)
        if override is not None:
            values[field_name] = override

    explicit_weights = getattr(overrides, "action_weight", None)
    if explicit_weights:
        weights = dict(values["action_weights"])
        weights.update(explicit_weights)
        values["action_weights"] = weights

    merged = vars(overrides).copy()
    merged.update(values)
    merged["profile"] = profile.name
    merged.pop("action_weight", None)
    args = argparse.Namespace(**merged)
    _validate_resolved_args(args)
    return args


def _validate_resolved_args(args: argparse.Namespace) -> None:
    raw = {
        "scenario": args.scenario,
        "users": args.users,
        "duration": args.duration,
        "ramp_up": args.ramp_up,
        "arrival_pattern": args.arrival_pattern,
        "rate": args.rate,
        "stage_rates": list(args.stage_rates),
        "spike_rate": args.spike_rate,
        "spike_start": args.spike_start,
        "spike_duration": args.spike_duration,
        "inflight_per_user": args.inflight_per_user,
        "payload_size": args.payload_size,
        "seed": args.seed,
        "action_weights": args.action_weights if args.scenario == "mixed" else None,
    }
    _profile_from_table(args.profile, raw)
    if args.no_ssl and (args.tls_ca_file is not None or args.insecure):
        raise ValueError("--tls-ca-file and --insecure require TLS")
    if args.insecure and args.tls_ca_file is not None:
        raise ValueError("--insecure cannot be combined with --tls-ca-file")
    remote = args.host is not None or args.port is not None
    if remote:
        if not args.target_id or not args.target_environment:
            raise ValueError("remote runs require --target-id and --target-environment")
        if not args.server_commit or not args.server_version:
            raise ValueError("remote runs require --server-commit and --server-version")
        if args.target_environment == "production":
            raise ValueError("performance tests must not target production")
        if args.scenario in MUTATING_SCENARIOS and (
            args.target_environment != "performance" or not args.allow_remote_mutations
        ):
            raise ValueError(
                "remote mutating scenarios require a performance target and "
                "--allow-remote-mutations"
            )
    elif args.target_id not in (None, "managed-disposable"):
        raise ValueError("managed runs use target id managed-disposable")

    if args.rate is not None and args.rate < 0:
        raise ValueError("--rate must be zero or positive")
    if args.arrival_pattern == "fixed" and args.rate <= 0:
        raise ValueError("fixed arrival pattern requires a positive rate")


def normalized_parameters(args: argparse.Namespace, *, account_pool_size: int) -> dict:
    return {
        "scenario": args.scenario,
        "users": args.users,
        "duration_seconds": args.duration,
        "ramp_up_seconds": args.ramp_up,
        "arrival_pattern": args.arrival_pattern,
        "rate": args.rate,
        "stage_rates": list(args.stage_rates),
        "spike_rate": args.spike_rate,
        "spike_start_seconds": args.spike_start,
        "spike_duration_seconds": args.spike_duration,
        "inflight_per_user": args.inflight_per_user,
        "payload_size_bytes": args.payload_size,
        "file_size_group": file_size_group(args.payload_size),
        "action_weights": dict(sorted(args.action_weights.items()))
        if args.scenario == "mixed"
        else {},
        "random_seed": args.seed,
        "account_pool_size": account_pool_size,
        "cleanup": "per-iteration-best-effort",
        "target_config_id": args.target_id or "managed-disposable",
        "target_environment": args.target_environment or "managed-disposable",
    }


def file_size_group(size: int) -> str:
    if size < 64 * 1024:
        return "lt-64KiB"
    if size < 1024 * 1024:
        return "64KiB-to-1MiB"
    if size < 16 * 1024 * 1024:
        return "1MiB-to-16MiB"
    return "ge-16MiB"
