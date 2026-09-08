import argparse
import asyncio
import hashlib
import json
import os
import random
import shutil
import ssl
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from statistics import mean
from subprocess import Popen
from tempfile import TemporaryDirectory

from tests.support.client import CFMSTestClient
from tests.support.config import (
    ConfigBackup,
    ServerTestSettings,
    capture_config,
    reserve_local_port,
    restore_config,
    write_test_config,
)
from tests.support.server import ServerLogCapture, start_server, stop_server

AUTHENTICATED_SCENARIOS = {
    "auth-read",
    "mixed",
    "upload-unique",
    "upload-duplicate",
}


@dataclass
class SampleStats:
    latencies_ms: list[float] = field(default_factory=list)
    errors: dict[str, int] = field(default_factory=dict)
    requests: int = 0
    successes: int = 0

    def record_success(self, latency_ms: float) -> None:
        self.requests += 1
        self.successes += 1
        self.latencies_ms.append(latency_ms)

    def record_error(
        self, error: BaseException | str, latency_ms: float | None
    ) -> None:
        self.requests += 1
        key = str(
            error.__class__.__name__ if isinstance(error, BaseException) else error
        )
        self.errors[key] = self.errors.get(key, 0) + 1
        if latency_ms is not None:
            self.latencies_ms.append(latency_ms)

    def merge(self, other: SampleStats) -> None:
        self.latencies_ms.extend(other.latencies_ms)
        self.requests += other.requests
        self.successes += other.successes
        for key, value in other.errors.items():
            self.errors[key] = self.errors.get(key, 0) + value


@dataclass
class LoadStats:
    total: SampleStats = field(default_factory=SampleStats)
    actions: dict[str, SampleStats] = field(default_factory=dict)
    dropped_iterations: int = 0

    def record_success(
        self, action: str, latency_ms: float, *, include_in_total: bool = True
    ) -> None:
        self.actions.setdefault(action, SampleStats()).record_success(latency_ms)
        if include_in_total:
            self.total.record_success(latency_ms)

    def record_error(
        self,
        action: str,
        error: BaseException | str,
        latency_ms: float | None,
        *,
        include_in_total: bool = True,
    ) -> None:
        self.actions.setdefault(action, SampleStats()).record_error(error, latency_ms)
        if include_in_total:
            self.total.record_error(error, latency_ms)

    def record_iteration_success(self, latency_ms: float) -> None:
        self.total.record_success(latency_ms)

    def record_iteration_error(
        self, error: BaseException | str, latency_ms: float | None
    ) -> None:
        self.total.record_error(error, latency_ms)

    def merge(self, other: LoadStats) -> None:
        self.total.merge(other.total)
        self.dropped_iterations += other.dropped_iterations
        for action, action_stats in other.actions.items():
            self.actions.setdefault(action, SampleStats()).merge(action_stats)


@dataclass
class FixedRatePacer:
    next_start: float
    interval: float
    deadline: float

    def next_slot(self, now: float) -> tuple[float | None, int]:
        deadline_tolerance = min(0.000001, self.interval / 1000)
        if self.next_start >= self.deadline - deadline_tolerance:
            return None, 0

        dropped = 0
        if now > self.next_start:
            dropped = int((now - self.next_start) // self.interval)
            self.next_start += dropped * self.interval

        scheduled = self.next_start
        self.next_start += self.interval
        if scheduled >= self.deadline - deadline_tolerance:
            return None, dropped
        return scheduled, dropped


@dataclass(frozen=True)
class LoadCredentials:
    username: str
    password: str = field(repr=False)


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, int((len(ordered) - 1) * pct))
    return ordered[index]


def summarize_samples(stats: SampleStats, elapsed: float) -> dict:
    latencies = stats.latencies_ms
    return {
        "requests": stats.requests,
        "successes": stats.successes,
        "errors": stats.errors,
        "success_rate": round(stats.successes / stats.requests, 4)
        if stats.requests
        else 0,
        "throughput_rps": round(stats.requests / elapsed, 3) if elapsed else 0,
        "latency_ms": {
            "avg": round(mean(latencies), 3) if latencies else 0,
            "p50": round(percentile(latencies, 0.50), 3),
            "p95": round(percentile(latencies, 0.95), 3),
            "p99": round(percentile(latencies, 0.99), 3),
            "max": round(max(latencies), 3) if latencies else 0,
        },
    }


def summarize(stats: LoadStats, elapsed: float, scenario: str, users: int) -> dict:
    return {
        "scenario": scenario,
        "users": users,
        "elapsed_seconds": round(elapsed, 3),
        **summarize_samples(stats.total, elapsed),
        "dropped_iterations": stats.dropped_iterations,
        "actions": {
            action: summarize_samples(action_stats, elapsed)
            for action, action_stats in sorted(stats.actions.items())
        },
    }


async def timed_call(
    stats: LoadStats,
    action: str,
    fn: Callable[[], Awaitable[dict]],
    *,
    include_in_total: bool = True,
) -> dict | None:
    start = time.perf_counter()
    try:
        response = await fn()
        latency_ms = (time.perf_counter() - start) * 1000
        if response.get("code") == 200:
            stats.record_success(action, latency_ms, include_in_total=include_in_total)
        else:
            stats.record_error(
                action,
                f"code_{response.get('code')}",
                latency_ms,
                include_in_total=include_in_total,
            )
        return response
    except Exception as exc:
        latency_ms = (time.perf_counter() - start) * 1000
        stats.record_error(action, exc, latency_ms, include_in_total=include_in_total)
        return None


async def timed_upload(
    stats: LoadStats,
    client: CFMSTestClient,
    task_id: str,
    payload_path: Path,
) -> bool:
    start = time.perf_counter()
    try:
        await client.upload_file_to_server(task_id, str(payload_path))
        stats.record_success(
            "upload_file",
            (time.perf_counter() - start) * 1000,
            include_in_total=False,
        )
        return True
    except Exception as exc:
        stats.record_error(
            "upload_file",
            exc,
            (time.perf_counter() - start) * 1000,
            include_in_total=False,
        )
        return False


def write_unique_payload(
    path: Path, payload_size: int, worker_id: int, sequence: int
) -> None:
    digest = hashlib.sha256(f"{worker_id}:{sequence}".encode()).digest()
    repeats, remainder = divmod(payload_size, len(digest))
    path.write_bytes(digest * repeats + digest[:remainder])


async def run_worker(
    worker_id: int,
    client: CFMSTestClient,
    scenario: str,
    start_time: float,
    deadline: float,
    ramp_delay: float,
    rate: float,
    users: int,
    seed: int,
    payload_size: int,
    payload_dir: Path,
) -> LoadStats:
    stats = LoadStats()
    rng = random.Random(seed + worker_id)
    pacer = None
    if rate:
        interval = users / rate
        first_start = start_time + ramp_delay
        if ramp_delay == 0:
            first_start += worker_id / rate
        pacer = FixedRatePacer(first_start, interval, deadline)
    elif ramp_delay:
        await asyncio.sleep(ramp_delay)

    sequence = 0
    while time.perf_counter() < deadline:
        if pacer is not None:
            scheduled, dropped = pacer.next_slot(time.perf_counter())
            stats.dropped_iterations += dropped
            if scheduled is None:
                break
            delay = scheduled - time.perf_counter()
            if delay > 0:
                await asyncio.sleep(delay)

        if scenario == "server-info":
            await timed_call(stats, "server_info", client.server_info)
        elif scenario == "auth-read":
            action, operation = rng.choice(
                [
                    ("list_directory", client.list_directory),
                    ("list_users", client.list_users),
                    ("list_groups", client.list_groups),
                ]
            )
            await timed_call(stats, action, operation)
        elif scenario == "mixed":
            roll = rng.random()
            if roll < 0.45:
                await timed_call(stats, "server_info", client.server_info)
            elif roll < 0.70:
                await timed_call(stats, "list_directory", client.list_directory)
            elif roll < 0.85:
                await timed_call(stats, "list_users", client.list_users)
            else:
                name = f"LoadDir_{worker_id}_{time.time_ns()}"
                await timed_call(
                    stats,
                    "create_directory",
                    lambda: client.create_directory(name),
                )
        elif scenario in {"upload-unique", "upload-duplicate"}:
            iteration_start = time.perf_counter()
            create_response = await timed_call(
                stats,
                "create_document",
                lambda: client.create_document(
                    f"LoadDoc_{scenario}_{worker_id}_{sequence}_{time.time_ns()}"
                ),
                include_in_total=False,
            )
            if create_response is None:
                stats.record_iteration_error(
                    "create_document_error",
                    (time.perf_counter() - iteration_start) * 1000,
                )
            elif create_response.get("code") != 200:
                stats.record_iteration_error(
                    f"code_{create_response.get('code')}",
                    (time.perf_counter() - iteration_start) * 1000,
                )
            else:
                if scenario == "upload-unique":
                    payload_path = payload_dir / f"unique-{worker_id}.bin"
                    write_unique_payload(
                        payload_path, payload_size, worker_id, sequence
                    )
                else:
                    payload_path = payload_dir / "duplicate.bin"
                uploaded = await timed_upload(
                    stats,
                    client,
                    create_response["data"]["task_data"]["task_id"],
                    payload_path,
                )
                latency_ms = (time.perf_counter() - iteration_start) * 1000
                if uploaded:
                    stats.record_iteration_success(latency_ms)
                else:
                    stats.record_iteration_error("upload_error", latency_ms)
            sequence += 1
        else:
            raise ValueError(f"Unknown scenario: {scenario}")

    return stats


def resolve_credentials(
    args: argparse.Namespace, *, managed: bool, src_dir: Path
) -> LoadCredentials | None:
    if args.scenario not in AUTHENTICATED_SCENARIOS:
        return None
    if managed:
        password = (src_dir / "admin_password.txt").read_text(encoding="utf-8").strip()
        return LoadCredentials("admin", password)

    username = args.username or os.environ.get("CFMS_LOAD_USERNAME")
    password = os.environ.get(args.password_env)
    missing = []
    if not username:
        missing.append("--username or CFMS_LOAD_USERNAME")
    if not password:
        missing.append(f"environment variable {args.password_env}")
    if missing:
        raise RuntimeError(
            "Remote authenticated scenarios require " + " and ".join(missing)
        )
    return LoadCredentials(username, password)


def create_load_ssl_context(
    *,
    use_ssl: bool,
    managed: bool,
    insecure: bool,
    tls_ca_file: Path | None,
) -> ssl.SSLContext | None:
    if not use_ssl:
        return None
    context = ssl.create_default_context(
        cafile=str(tls_ca_file) if tls_ca_file is not None else None
    )
    if managed or insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


async def prepare_clients(
    settings: ServerTestSettings,
    users: int,
    credentials: LoadCredentials | None,
    ssl_context: ssl.SSLContext | None,
) -> list[CFMSTestClient]:
    clients = [
        CFMSTestClient(
            host=settings.host,
            port=settings.port,
            use_ssl=settings.use_ssl,
            ssl_context=ssl_context,
        )
        for _ in range(users)
    ]
    try:
        await asyncio.gather(*(client.connect() for client in clients))
        if credentials is not None:
            responses = await asyncio.gather(
                *(
                    client.login(credentials.username, credentials.password)
                    for client in clients
                )
            )
            failures = [
                response.get("code")
                for response in responses
                if response.get("code") != 200
            ]
            if failures:
                raise RuntimeError(
                    f"Load-test authentication failed with response codes: {failures}"
                )
    except BaseException:
        await asyncio.gather(
            *(client.disconnect() for client in clients), return_exceptions=True
        )
        raise
    return clients


def prepare_managed_server(
    src_dir: Path,
    *,
    debug: bool = False,
) -> tuple[ServerTestSettings, ConfigBackup, tuple[Popen, ServerLogCapture]]:
    backup = capture_config(src_dir / "config.toml")
    settings = write_test_config(src_dir, reserve_local_port(), debug=debug)
    for key, value in {
        "CFMS_TEST_HOST": settings.host,
        "CFMS_TEST_PORT": str(settings.port),
        "CFMS_TEST_USE_SSL": "1" if settings.use_ssl else "0",
    }.items():
        os.environ[key] = value
    for name in ("init", "app.db", "admin_password.txt"):
        path = src_dir / name
        if path.exists():
            path.unlink()
    storage_path = src_dir / "content" / "files"
    if storage_path.exists():
        shutil.rmtree(storage_path)
    (src_dir / "content" / "ssl").mkdir(parents=True, exist_ok=True)
    (src_dir / "content" / "logs").mkdir(parents=True, exist_ok=True)
    process, logs = start_server(settings)
    return settings, backup, (process, logs)


async def run_load(args) -> dict:
    repo_root = Path(__file__).resolve().parents[2]
    src_dir = repo_root / "src"
    managed = args.host is None and args.port is None
    backup = None
    server = None
    clients: list[CFMSTestClient] = []

    if managed:
        if not args.managed_reset:
            raise RuntimeError(
                "Managed mode deletes src/app.db and src/content/files; "
                "rerun in a disposable worktree with --managed-reset"
            )
        settings, backup, server = prepare_managed_server(src_dir, debug=args.debug)
    else:
        settings = ServerTestSettings(
            host=args.host or os.environ.get("CFMS_TEST_HOST", "localhost"),
            port=args.port
            if args.port is not None
            else int(os.environ.get("CFMS_TEST_PORT", "5104")),
            use_ssl=not args.no_ssl,
            src_dir=src_dir,
            config_path=src_dir / "config.toml",
        )

    try:
        credentials = resolve_credentials(args, managed=managed, src_dir=src_dir)
        ssl_context = create_load_ssl_context(
            use_ssl=settings.use_ssl,
            managed=managed,
            insecure=args.insecure,
            tls_ca_file=args.tls_ca_file,
        )
        clients = await prepare_clients(settings, args.users, credentials, ssl_context)
        with TemporaryDirectory(prefix="cfms-upload-load-") as payload_directory:
            payload_dir = Path(payload_directory)
            (payload_dir / "duplicate.bin").write_bytes(b"d" * args.payload_size)
            start = time.perf_counter()
            deadline = start + args.duration
            ramp_step = args.ramp_up / max(args.users - 1, 1)
            worker_stats = await asyncio.gather(
                *[
                    run_worker(
                        worker_id,
                        client,
                        args.scenario,
                        start,
                        deadline,
                        ramp_step * worker_id,
                        args.rate,
                        args.users,
                        args.seed,
                        args.payload_size,
                        payload_dir,
                    )
                    for worker_id, client in enumerate(clients)
                ]
            )
            elapsed = max(time.perf_counter() - start, args.duration)
        total = LoadStats()
        for stats in worker_stats:
            total.merge(stats)
        result = summarize(total, elapsed, args.scenario, args.users)
        result["parameters"] = {
            "duration_seconds": args.duration,
            "ramp_up_seconds": args.ramp_up,
            "rate": args.rate,
            "rate_model": "fixed-arrival" if args.rate else "closed",
            "seed": args.seed,
            "payload_size_bytes": args.payload_size,
        }
        return result
    finally:
        if clients:
            await asyncio.gather(
                *(client.disconnect() for client in clients), return_exceptions=True
            )
        if server is not None:
            process, logs = server
            stop_server(process, logs)
        if backup is not None:
            restore_config(backup)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CFMS WebSocket load test tool")
    parser.add_argument("--users", type=int, default=8)
    parser.add_argument("--duration", type=float, default=30)
    parser.add_argument("--ramp-up", type=float, default=0)
    parser.add_argument(
        "--rate",
        type=float,
        default=0,
        help="Global scheduled iteration rate",
    )
    parser.add_argument(
        "--scenario",
        choices=[
            "server-info",
            "auth-read",
            "mixed",
            "upload-unique",
            "upload-duplicate",
        ],
        default="server-info",
    )
    parser.add_argument("--host")
    parser.add_argument("--port", type=int)
    parser.add_argument("--no-ssl", action="store_true")
    parser.add_argument(
        "--tls-ca-file",
        type=Path,
        help="CA bundle for remote TLS verification",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable remote TLS verification; use only with disposable targets",
    )
    parser.add_argument(
        "--username",
        help="Remote username; defaults to CFMS_LOAD_USERNAME",
    )
    parser.add_argument(
        "--password-env",
        default="CFMS_LOAD_PASSWORD",
        help="Environment variable containing the remote password",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable server debug mode and verbose SQL logging in managed mode",
    )
    parser.add_argument(
        "--managed-reset",
        action="store_true",
        help="Allow managed mode to reset runtime database and file storage",
    )
    parser.add_argument("--payload-size", type=int, default=256 * 1024)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if args.users <= 0:
        parser.error("--users must be positive")
    if args.duration <= 0:
        parser.error("--duration must be positive")
    if args.ramp_up < 0 or args.ramp_up >= args.duration:
        parser.error("--ramp-up must be at least zero and less than --duration")
    if args.rate < 0:
        parser.error("--rate must be zero or positive")
    if args.payload_size <= 0:
        parser.error("--payload-size must be positive")
    if args.scenario == "upload-unique" and args.payload_size < 32:
        parser.error("upload-unique requires --payload-size of at least 32 bytes")
    if args.no_ssl and (args.tls_ca_file is not None or args.insecure):
        parser.error("--tls-ca-file and --insecure require TLS")
    if args.insecure and args.tls_ca_file is not None:
        parser.error("--insecure cannot be combined with --tls-ca-file")
    return args


def main() -> None:
    args = parse_args()
    result = asyncio.run(run_load(args))
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"Scenario: {result['scenario']}")
        print(f"Users: {result['users']}")
        print(f"Requests: {result['requests']}")
        print(f"Success rate: {result['success_rate']:.2%}")
        print(f"Throughput: {result['throughput_rps']} req/s")
        print(f"Dropped iterations: {result['dropped_iterations']}")
        print(f"Latency: {result['latency_ms']}")
        print(f"Errors: {result['errors']}")
        print(f"Actions: {result['actions']}")


if __name__ == "__main__":
    main()
