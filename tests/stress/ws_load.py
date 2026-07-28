import argparse
import asyncio
import hashlib
import json
import os
import random
import shutil
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from statistics import mean
from subprocess import Popen
from tempfile import TemporaryDirectory

from tests.support.server import ServerLogCapture, start_server, stop_server
from tests.support.test_config import (
    ConfigBackup,
    ServerTestSettings,
    capture_config,
    reserve_local_port,
    restore_config,
    write_test_config,
)
from tests.test_client import CFMSTestClient


@dataclass
class LoadStats:
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

    def merge(self, other: LoadStats) -> None:
        self.latencies_ms.extend(other.latencies_ms)
        self.requests += other.requests
        self.successes += other.successes
        for key, value in other.errors.items():
            self.errors[key] = self.errors.get(key, 0) + value


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, int((len(ordered) - 1) * pct))
    return ordered[index]


def summarize(stats: LoadStats, elapsed: float, scenario: str, users: int) -> dict:
    latencies = stats.latencies_ms
    return {
        "scenario": scenario,
        "users": users,
        "elapsed_seconds": round(elapsed, 3),
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


async def timed_call(stats: LoadStats, fn: Callable[[], Awaitable[dict]]) -> None:
    start = time.perf_counter()
    try:
        response = await fn()
        latency_ms = (time.perf_counter() - start) * 1000
        if response.get("code") == 200:
            stats.record_success(latency_ms)
        else:
            stats.record_error(f"code_{response.get('code')}", latency_ms)
    except Exception as exc:
        latency_ms = (time.perf_counter() - start) * 1000
        stats.record_error(exc, latency_ms)


async def timed_upload(
    stats: LoadStats,
    client: CFMSTestClient,
    task_id: str,
    payload_path: Path,
) -> None:
    start = time.perf_counter()
    try:
        await client.upload_file_to_server(task_id, str(payload_path))
        stats.record_success((time.perf_counter() - start) * 1000)
    except Exception as exc:
        stats.record_error(exc, (time.perf_counter() - start) * 1000)


def write_unique_payload(
    path: Path, payload_size: int, worker_id: int, sequence: int
) -> None:
    digest = hashlib.sha256(f"{worker_id}:{sequence}".encode()).digest()
    repeats, remainder = divmod(payload_size, len(digest))
    path.write_bytes(digest * repeats + digest[:remainder])


async def run_worker(
    worker_id: int,
    settings: ServerTestSettings,
    scenario: str,
    deadline: float,
    ramp_up: float,
    per_worker_interval: float,
    payload_size: int,
    payload_dir: Path,
) -> LoadStats:
    stats = LoadStats()
    if ramp_up > 0:
        await asyncio.sleep(ramp_up * worker_id)

    client = CFMSTestClient(
        host=settings.host,
        port=settings.port,
        use_ssl=settings.use_ssl,
    )
    await client.connect()
    try:
        if scenario in {"auth-read", "mixed", "upload-unique", "upload-duplicate"}:
            password = (
                (settings.src_dir / "admin_password.txt")
                .read_text(encoding="utf-8")
                .strip()
            )
            if scenario.startswith("upload-"):
                login_response = await client.login("admin", password)
                if login_response.get("code") != 200:
                    raise RuntimeError(
                        f"Upload benchmark login failed: {login_response.get('code')}"
                    )
            else:
                await timed_call(stats, lambda: client.login("admin", password))

        sequence = 0
        while time.perf_counter() < deadline:
            if scenario == "server-info":
                await timed_call(stats, client.server_info)
            elif scenario == "auth-read":
                operation = random.choice(
                    [
                        client.list_directory,
                        client.list_users,
                        client.list_groups,
                    ]
                )
                await timed_call(stats, operation)
            elif scenario == "mixed":
                roll = random.random()
                if roll < 0.45:
                    await timed_call(stats, client.server_info)
                elif roll < 0.70:
                    await timed_call(stats, client.list_directory)
                elif roll < 0.85:
                    await timed_call(stats, client.list_users)
                else:
                    name = f"LoadDir_{worker_id}_{time.time_ns()}"
                    await timed_call(stats, lambda: client.create_directory(name))
            elif scenario in {"upload-unique", "upload-duplicate"}:
                create_response = await client.create_document(
                    f"LoadDoc_{scenario}_{worker_id}_{sequence}_{time.time_ns()}"
                )
                if create_response.get("code") != 200:
                    stats.record_error(f"code_{create_response.get('code')}", None)
                else:
                    if scenario == "upload-unique":
                        payload_path = payload_dir / f"unique-{worker_id}.bin"
                        write_unique_payload(
                            payload_path, payload_size, worker_id, sequence
                        )
                    else:
                        payload_path = payload_dir / "duplicate.bin"
                    await timed_upload(
                        stats,
                        client,
                        create_response["data"]["task_data"]["task_id"],
                        payload_path,
                    )
                sequence += 1
            else:
                raise ValueError(f"Unknown scenario: {scenario}")

            if per_worker_interval > 0:
                await asyncio.sleep(per_worker_interval)
    finally:
        await client.disconnect()

    return stats


def prepare_managed_server(
    src_dir: Path,
) -> tuple[ServerTestSettings, ConfigBackup, tuple[Popen, ServerLogCapture]]:
    backup = capture_config(src_dir / "config.toml")
    settings = write_test_config(src_dir, reserve_local_port())
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

    if managed:
        if not args.managed_reset:
            raise RuntimeError(
                "Managed mode deletes src/app.db and src/content/files; "
                "rerun in a disposable worktree with --managed-reset"
            )
        settings, backup, server = prepare_managed_server(src_dir)
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
        with TemporaryDirectory(prefix="cfms-upload-load-") as payload_directory:
            payload_dir = Path(payload_directory)
            (payload_dir / "duplicate.bin").write_bytes(b"d" * args.payload_size)
            start = time.perf_counter()
            deadline = start + args.duration
            per_worker_interval = args.users / args.rate if args.rate else 0
            ramp_step = args.ramp_up / max(args.users - 1, 1)
            worker_stats = await asyncio.gather(
                *[
                    run_worker(
                        worker_id,
                        settings,
                        args.scenario,
                        deadline,
                        ramp_step,
                        per_worker_interval,
                        args.payload_size,
                        payload_dir,
                    )
                    for worker_id in range(args.users)
                ]
            )
            elapsed = time.perf_counter() - start
        total = LoadStats()
        for stats in worker_stats:
            total.merge(stats)
        result = summarize(total, elapsed, args.scenario, args.users)
        result["parameters"] = {
            "duration_seconds": args.duration,
            "ramp_up_seconds": args.ramp_up,
            "rate": args.rate,
            "payload_size_bytes": args.payload_size,
        }
        return result
    finally:
        if server is not None:
            process, logs = server
            stop_server(process, logs)
        if backup is not None:
            restore_config(backup)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CFMS WebSocket load test tool")
    parser.add_argument("--users", type=int, default=20)
    parser.add_argument("--duration", type=float, default=30)
    parser.add_argument("--ramp-up", type=float, default=0)
    parser.add_argument("--rate", type=float, default=0, help="Global request rate cap")
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
        "--managed-reset",
        action="store_true",
        help="Allow managed mode to reset runtime database and file storage",
    )
    parser.add_argument("--payload-size", type=int, default=256 * 1024)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if args.payload_size <= 0:
        parser.error("--payload-size must be positive")
    if args.scenario == "upload-unique" and args.payload_size < 32:
        parser.error("upload-unique requires --payload-size of at least 32 bytes")
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
        print(f"Latency: {result['latency_ms']}")
        print(f"Errors: {result['errors']}")


if __name__ == "__main__":
    main()
