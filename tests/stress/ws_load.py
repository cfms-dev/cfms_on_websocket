import argparse
import asyncio
import hashlib
import json
import os
import platform
import random
import shutil
import ssl
import subprocess
import time
import tomllib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from subprocess import Popen
from tempfile import TemporaryDirectory

from websockets.exceptions import ConnectionClosed, InvalidStatus

from tests.stress.load_config import (
    AUTHENTICATED_SCENARIOS,
    DEFAULT_PROFILE_PATH,
    SCENARIOS,
    apply_profile_overrides,
    load_profiles,
    normalized_parameters,
    parse_action_weight,
    parse_duration,
    parse_stage_rates,
)
from tests.stress.load_metrics import (
    ConnectionStats,
    GeneratorHealth,
    LoadStats,
    monitor_generator,
    summarize_samples,
)
from tests.support.client import CFMSTestClient, DownloadCheckpoint
from tests.support.config import (
    ConfigBackup,
    ServerTestSettings,
    capture_config,
    reserve_local_port,
    restore_config,
    write_test_config,
)
from tests.support.server import ServerLogCapture, start_server, stop_server


@dataclass(frozen=True)
class LoadCredentials:
    username: str
    password: str = field(repr=False)


@dataclass(frozen=True)
class LoadPhase:
    name: str
    duration_seconds: float
    rate: float


@dataclass
class WorkerContext:
    worker_id: int
    client: CFMSTestClient
    credentials: LoadCredentials | None
    settings: ServerTestSettings
    ssl_context: ssl.SSLContext | None
    connection_stats: ConnectionStats
    payload_dir: Path
    created_directories: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class FileIteration:
    document_id: str
    upload_task_id: str


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


def _valid_rejection(response: dict, expected_codes: set[int]) -> str | None:
    code = response.get("code")
    if code not in expected_codes:
        return None
    data = response.get("data")
    if not isinstance(data, dict):
        return None
    scope = data.get("scope")
    retry_after = data.get("retry_after_seconds")
    if (
        not isinstance(scope, str)
        or not scope
        or isinstance(retry_after, bool)
        or not isinstance(retry_after, int | float)
        or retry_after <= 0
    ):
        return None
    if code == 429:
        limit = data.get("limit")
        if isinstance(limit, bool) or not isinstance(limit, int | float) or limit <= 0:
            return None
    return f"code_{code}:{scope}"


async def timed_call(
    stats: LoadStats,
    action: str,
    fn: Callable[[], Awaitable[dict]],
    *,
    include_in_total: bool = True,
    expected_rejection_codes: set[int] | None = None,
) -> dict | None:
    start = time.perf_counter()
    try:
        response = await fn()
        latency_ms = (time.perf_counter() - start) * 1000
        if response.get("code") == 200:
            stats.record_success(action, latency_ms, include_in_total=include_in_total)
        elif (
            expected_rejection_codes
            and response.get("code") in expected_rejection_codes
        ):
            rejection = _valid_rejection(response, expected_rejection_codes)
            if rejection is None:
                stats.record_error(
                    action,
                    f"invalid_rejection_contract_{response.get('code')}",
                    latency_ms,
                    include_in_total=include_in_total,
                )
            else:
                stats.record_expected_rejection(
                    action,
                    rejection,
                    latency_ms,
                    include_in_total=include_in_total,
                )
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


def write_unique_payload(
    path: Path, payload_size: int, worker_id: int, sequence: int
) -> None:
    digest = hashlib.sha256(f"{worker_id}:{sequence}".encode()).digest()
    repeats, remainder = divmod(payload_size, len(digest))
    path.write_bytes(digest * repeats + digest[:remainder])


def load_account_pool(path: Path) -> list[LoadCredentials]:
    try:
        with path.open("rb") as account_file:
            document = tomllib.load(account_file)
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"Invalid account pool TOML in {path}: {exc}") from exc
    unknown = set(document) - {"schema_version", "accounts"}
    if unknown:
        raise ValueError(f"Unknown account pool fields: {sorted(unknown)}")
    if document.get("schema_version") != 1:
        raise ValueError("account pool schema_version must be 1")
    rows = document.get("accounts")
    if not isinstance(rows, list) or not rows:
        raise ValueError("account pool must contain at least one [[accounts]] entry")
    credentials = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or set(row) != {"username", "password_env"}:
            raise ValueError(
                f"account pool entry {index} must contain only username and password_env"
            )
        username = row["username"]
        password_env = row["password_env"]
        if not isinstance(username, str) or not username:
            raise ValueError(f"account pool entry {index} has an invalid username")
        if not isinstance(password_env, str) or not password_env:
            raise ValueError(f"account pool entry {index} has an invalid password_env")
        password = os.environ.get(password_env)
        if not password:
            raise RuntimeError(
                f"account pool entry {index} requires environment variable {password_env}"
            )
        credentials.append(LoadCredentials(username, password))
    return credentials


def resolve_credentials(
    args: argparse.Namespace, *, managed: bool, src_dir: Path
) -> list[LoadCredentials]:
    if args.scenario not in AUTHENTICATED_SCENARIOS:
        return []
    if managed:
        password = (src_dir / "admin_password.txt").read_text(encoding="utf-8").strip()
        return [LoadCredentials("admin", password)]
    if args.accounts_file is not None:
        return load_account_pool(args.accounts_file)
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
    return [LoadCredentials(username, password)]


def create_load_ssl_context(
    *, use_ssl: bool, managed: bool, insecure: bool, tls_ca_file: Path | None
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


def _find_invalid_status(error: BaseException) -> InvalidStatus | None:
    current: BaseException | None = error
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, InvalidStatus):
            return current
        current = current.__cause__ or current.__context__
    return None


def _valid_handshake_rejection(error: BaseException) -> str | None:
    invalid_status = _find_invalid_status(error)
    if invalid_status is None or invalid_status.response.status_code != 429:
        return None
    retry_after = invalid_status.response.headers.get("Retry-After")
    if retry_after is None:
        return None
    try:
        if float(retry_after) <= 0:
            return None
    except ValueError:
        return None
    return "http_429:connection_attempt"


async def connect_client(
    client: CFMSTestClient,
    stats: ConnectionStats,
    *,
    expected_rejection: bool = False,
) -> bool:
    start = time.perf_counter()
    try:
        await client.connect(max_retries=1)
    except Exception as exc:
        latency_ms = (time.perf_counter() - start) * 1000
        rejection = _valid_handshake_rejection(exc) if expected_rejection else None
        if rejection is not None:
            stats.rejected(rejection, latency_ms)
        else:
            stats.failed(exc, latency_ms)
        return False
    stats.connected((time.perf_counter() - start) * 1000)
    return True


async def disconnect_client(client: CFMSTestClient, stats: ConnectionStats) -> None:
    was_connected = client.websocket is not None
    await client.disconnect()
    if was_connected:
        stats.disconnected()


async def login_client(
    client: CFMSTestClient,
    credentials: LoadCredentials,
    stats: LoadStats,
) -> None:
    response = await timed_call(
        stats,
        "login",
        lambda: client.login(credentials.username, credentials.password),
        include_in_total=False,
    )
    if response is None or response.get("code") != 200:
        raise RuntimeError(
            "Load-test authentication failed with response code "
            f"{None if response is None else response.get('code')}"
        )


async def prepare_contexts(
    settings: ServerTestSettings,
    users: int,
    credentials: list[LoadCredentials],
    ssl_context: ssl.SSLContext | None,
    connection_stats: ConnectionStats,
    payload_dir: Path,
) -> tuple[list[WorkerContext], LoadStats]:
    setup_stats = LoadStats()
    contexts = []
    for worker_id in range(users):
        credential = credentials[worker_id % len(credentials)] if credentials else None
        contexts.append(
            WorkerContext(
                worker_id=worker_id,
                client=CFMSTestClient(
                    host=settings.host,
                    port=settings.port,
                    use_ssl=settings.use_ssl,
                    ssl_context=ssl_context,
                ),
                credentials=credential,
                settings=settings,
                ssl_context=ssl_context,
                connection_stats=connection_stats,
                payload_dir=payload_dir,
            )
        )
    try:
        connected = await asyncio.gather(
            *(connect_client(context.client, connection_stats) for context in contexts)
        )
        if not all(connected):
            raise RuntimeError("One or more load-test clients failed to connect")
        await asyncio.gather(
            *(
                login_client(context.client, context.credentials, setup_stats)
                for context in contexts
                if context.credentials is not None
            )
        )
    except BaseException:
        await asyncio.gather(
            *(
                disconnect_client(context.client, connection_stats)
                for context in contexts
            ),
            return_exceptions=True,
        )
        raise
    return contexts, setup_stats


async def reconnect_context(context: WorkerContext, stats: LoadStats) -> None:
    await disconnect_client(context.client, context.connection_stats)
    context.client = CFMSTestClient(
        host=context.settings.host,
        port=context.settings.port,
        use_ssl=context.settings.use_ssl,
        ssl_context=context.ssl_context,
    )
    if not await connect_client(context.client, context.connection_stats):
        raise ConnectionError("Reconnect failed")
    if context.credentials is not None:
        await login_client(context.client, context.credentials, stats)


def _select_weighted_action(rng: random.Random, weights: dict[str, float]) -> str:
    roll = rng.random() * sum(weights.values())
    cumulative = 0.0
    for action, weight in weights.items():
        cumulative += weight
        if roll < cumulative:
            return action
    return next(reversed(weights))


async def run_mixed_action(
    context: WorkerContext,
    stats: LoadStats,
    rng: random.Random,
    sequence: int,
    weights: dict[str, float],
) -> None:
    action = _select_weighted_action(rng, weights)
    if action == "read":
        await timed_call(stats, "list_directory", context.client.list_directory)
        return
    if action == "create" or not context.created_directories:
        response = await timed_call(
            stats,
            "create_directory",
            lambda: context.client.create_directory(
                f"Perf_{context.worker_id}_{sequence}_{time.time_ns()}"
            ),
        )
        if response is not None and response.get("code") == 200:
            directory_id = response.get("data", {}).get("id")
            if isinstance(directory_id, str):
                context.created_directories.append(directory_id)
        return
    directory_id = context.created_directories[-1]
    if action == "update":
        await timed_call(
            stats,
            "rename_directory",
            lambda: context.client.send_request(
                "rename_directory",
                {
                    "folder_id": directory_id,
                    "new_name": (
                        f"PerfRenamed_{context.worker_id}_{sequence}_{time.time_ns()}"
                    ),
                },
            ),
        )
        return
    response = await timed_call(
        stats,
        "delete_directory",
        lambda: context.client.delete_directory(directory_id),
    )
    if response is not None and response.get("code") == 200:
        context.created_directories.pop()
        await timed_call(
            stats,
            "cleanup_purge_directory",
            lambda: context.client.purge_directory(directory_id),
            include_in_total=False,
        )


async def _create_file_iteration(
    context: WorkerContext,
    stats: LoadStats,
    title: str,
) -> FileIteration | None:
    response = await timed_call(
        stats,
        "create_document",
        lambda: context.client.create_document(title),
        include_in_total=False,
    )
    if response is None or response.get("code") != 200:
        return None
    data = response.get("data", {})
    document_id = data.get("document_id")
    task_id = data.get("task_data", {}).get("task_id")
    if not isinstance(document_id, str) or not isinstance(task_id, str):
        stats.record_error(
            "create_document",
            "invalid_create_document_contract",
            None,
            include_in_total=False,
        )
        return None
    return FileIteration(document_id, task_id)


async def _cleanup_document(
    context: WorkerContext, stats: LoadStats, document_id: str
) -> None:
    deleted = await timed_call(
        stats,
        "cleanup_delete_document",
        lambda: context.client.delete_document(document_id),
        include_in_total=False,
    )
    if deleted is not None and deleted.get("code") == 200:
        await timed_call(
            stats,
            "cleanup_purge_document",
            lambda: context.client.purge_document(document_id),
            include_in_total=False,
        )


async def _upload_payload(
    context: WorkerContext,
    stats: LoadStats,
    task_id: str,
    payload_path: Path,
    *,
    resume: bool,
) -> bool:
    start = time.perf_counter()
    try:
        if resume and payload_path.stat().st_size > 1:
            interrupted_at = await context.client.upload_file_to_server(
                task_id,
                str(payload_path),
                interrupt_after_bytes=max(1, payload_path.stat().st_size // 2),
            )
            if not isinstance(interrupted_at, int):
                raise RuntimeError("Upload did not produce a resume checkpoint")
            await reconnect_context(context, stats)
        await context.client.upload_file_to_server(task_id, str(payload_path))
    except Exception as exc:
        stats.record_error(
            "upload_file_resume" if resume else "upload_file",
            exc,
            (time.perf_counter() - start) * 1000,
            include_in_total=False,
        )
        return False
    stats.record_success(
        "upload_file_resume" if resume else "upload_file",
        (time.perf_counter() - start) * 1000,
        include_in_total=False,
        transferred_bytes=payload_path.stat().st_size,
    )
    return True


async def _current_revision_id(
    context: WorkerContext, stats: LoadStats, document_id: str
) -> str | None:
    response = await timed_call(
        stats,
        "list_revisions",
        lambda: context.client.list_revisions(document_id),
        include_in_total=False,
    )
    if response is None or response.get("code") != 200:
        return None
    items = response.get("data", {}).get("items", [])
    for item in items:
        if (
            isinstance(item, dict)
            and item.get("is_current")
            and isinstance(item.get("id"), str)
        ):
            return item["id"]
    stats.record_error(
        "list_revisions",
        "invalid_current_revision_contract",
        None,
        include_in_total=False,
    )
    return None


async def _download_payload(
    context: WorkerContext,
    stats: LoadStats,
    revision_id: str,
    destination: Path,
    payload_size: int,
    *,
    resume: bool,
) -> bool:
    task_response = await timed_call(
        stats,
        "get_revision",
        lambda: context.client.get_revision(revision_id),
        include_in_total=False,
    )
    if task_response is None or task_response.get("code") != 200:
        return False
    task_id = task_response.get("data", {}).get("task_data", {}).get("task_id")
    if not isinstance(task_id, str):
        stats.record_error(
            "get_revision",
            "invalid_download_task_contract",
            None,
            include_in_total=False,
        )
        return False
    start = time.perf_counter()
    try:
        checkpoint: DownloadCheckpoint | None = None
        if resume and payload_size > 64 * 1024:
            checkpoint = await context.client.download_file_from_server(
                task_id,
                str(destination),
                interrupt_after_bytes=max(64 * 1024, payload_size // 2),
            )
            if checkpoint is None or checkpoint.offset <= 0:
                raise RuntimeError("Download did not produce a resume checkpoint")
            await reconnect_context(context, stats)
        completed = await context.client.download_file_from_server(
            task_id,
            str(destination),
            resume_state=checkpoint,
        )
        if completed is not None:
            raise RuntimeError("Download did not reach completion")
        if destination.stat().st_size != payload_size:
            raise RuntimeError("Downloaded file size does not match source")
    except Exception as exc:
        stats.record_error(
            "download_file_resume" if resume else "download_file",
            exc,
            (time.perf_counter() - start) * 1000,
            include_in_total=False,
        )
        return False
    stats.record_success(
        "download_file_resume" if resume else "download_file",
        (time.perf_counter() - start) * 1000,
        include_in_total=False,
        transferred_bytes=payload_size,
    )
    return True


async def run_file_iteration(
    context: WorkerContext,
    stats: LoadStats,
    scenario: str,
    sequence: int,
    payload_size: int,
) -> None:
    iteration_start = time.perf_counter()
    file_iteration = await _create_file_iteration(
        context,
        stats,
        f"Perf_{scenario}_{context.worker_id}_{sequence}_{time.time_ns()}",
    )
    if file_iteration is None:
        stats.record_iteration_error(
            "create_document_error",
            (time.perf_counter() - iteration_start) * 1000,
        )
        return
    try:
        if scenario == "upload-unique":
            payload_path = context.payload_dir / f"unique-{context.worker_id}.bin"
            write_unique_payload(
                payload_path, payload_size, context.worker_id, sequence
            )
        else:
            payload_path = context.payload_dir / "duplicate.bin"
        uploaded = await _upload_payload(
            context,
            stats,
            file_iteration.upload_task_id,
            payload_path,
            resume=scenario == "upload-resume",
        )
        if not uploaded:
            stats.record_iteration_error(
                "upload_error", (time.perf_counter() - iteration_start) * 1000
            )
            return
        if scenario in {"download", "download-resume"}:
            revision_id = await _current_revision_id(
                context, stats, file_iteration.document_id
            )
            if revision_id is None:
                stats.record_iteration_error(
                    "revision_lookup_error",
                    (time.perf_counter() - iteration_start) * 1000,
                )
                return
            destination = (
                context.payload_dir
                / f"download-{context.worker_id}-{sequence}-{time.time_ns()}.bin"
            )
            downloaded = await _download_payload(
                context,
                stats,
                revision_id,
                destination,
                payload_size,
                resume=scenario == "download-resume",
            )
            destination.unlink(missing_ok=True)
            if not downloaded:
                stats.record_iteration_error(
                    "download_error",
                    (time.perf_counter() - iteration_start) * 1000,
                )
                return
        stats.record_iteration_success(
            (time.perf_counter() - iteration_start) * 1000,
            transferred_bytes=payload_size,
        )
    finally:
        await _cleanup_document(context, stats, file_iteration.document_id)


async def _run_connection_cycle(
    context: WorkerContext,
    stats: LoadStats,
    reconnect: bool,
) -> None:
    start = time.perf_counter()
    attempts = 2 if reconnect else 1
    for _ in range(attempts):
        client = CFMSTestClient(
            host=context.settings.host,
            port=context.settings.port,
            use_ssl=context.settings.use_ssl,
            ssl_context=context.ssl_context,
        )
        expected_before = sum(context.connection_stats.expected_rejections.values())
        connected = await connect_client(
            client,
            context.connection_stats,
            expected_rejection=True,
        )
        if not connected:
            expected_after = sum(context.connection_stats.expected_rejections.values())
            if expected_after > expected_before:
                stats.record_expected_rejection(
                    "connection",
                    "http_429:connection_attempt",
                    (time.perf_counter() - start) * 1000,
                )
            else:
                stats.record_error(
                    "connection",
                    "connection_failed",
                    (time.perf_counter() - start) * 1000,
                )
            return
        try:
            response = await client.server_info()
            if response.get("code") != 200:
                stats.record_error(
                    "connection",
                    f"code_{response.get('code')}",
                    (time.perf_counter() - start) * 1000,
                )
                return
        except ConnectionClosed as exc:
            if exc.code == 1013:
                stats.record_expected_rejection(
                    "connection",
                    "close_1013:connection_capacity",
                    (time.perf_counter() - start) * 1000,
                )
            else:
                stats.record_error(
                    "connection", exc, (time.perf_counter() - start) * 1000
                )
            return
        except Exception as exc:
            close_code = getattr(client.websocket, "close_code", None)
            if close_code == 1013:
                stats.record_expected_rejection(
                    "connection",
                    "close_1013:connection_capacity",
                    (time.perf_counter() - start) * 1000,
                )
            else:
                stats.record_error(
                    "connection", exc, (time.perf_counter() - start) * 1000
                )
            return
        finally:
            await disconnect_client(client, context.connection_stats)
    stats.record_success("connection", (time.perf_counter() - start) * 1000)


async def run_worker_phase(
    context: WorkerContext,
    args: argparse.Namespace,
    phase: LoadPhase,
    start_time: float,
    ramp_delay: float,
) -> LoadStats:
    stats = LoadStats()
    rng = random.Random(args.seed + context.worker_id)
    deadline = start_time + phase.duration_seconds
    pacer = None
    if phase.rate:
        interval = args.users / phase.rate
        first_start = start_time + ramp_delay
        if ramp_delay == 0:
            first_start += context.worker_id / phase.rate
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
        if args.scenario == "server-info":
            await timed_call(stats, "server_info", context.client.server_info)
        elif args.scenario == "auth-read":
            action, operation = rng.choice(
                [
                    ("list_directory", context.client.list_directory),
                    ("list_users", context.client.list_users),
                    ("list_groups", context.client.list_groups),
                ]
            )
            await timed_call(stats, action, operation)
        elif args.scenario == "mixed":
            await run_mixed_action(
                context,
                stats,
                rng,
                sequence,
                args.action_weights,
            )
        elif args.scenario == "multiplex":
            await asyncio.gather(
                *(
                    timed_call(stats, "server_info", context.client.server_info)
                    for _ in range(args.inflight_per_user)
                )
            )
        elif args.scenario == "admission-control":
            await asyncio.gather(
                *(
                    timed_call(
                        stats,
                        "server_info",
                        context.client.server_info,
                        expected_rejection_codes={503},
                    )
                    for _ in range(args.inflight_per_user)
                )
            )
        elif args.scenario == "request-rate-control":
            await timed_call(
                stats,
                "server_info",
                context.client.server_info,
                expected_rejection_codes={429},
            )
        elif args.scenario in {
            "upload-unique",
            "upload-duplicate",
            "upload-resume",
            "download",
            "download-resume",
        }:
            await run_file_iteration(
                context, stats, args.scenario, sequence, args.payload_size
            )
        elif args.scenario in {"connection-storm", "reconnect-storm"}:
            await _run_connection_cycle(
                context, stats, reconnect=args.scenario == "reconnect-storm"
            )
        else:
            raise ValueError(f"Unknown scenario: {args.scenario}")
        sequence += 1
    return stats


async def cleanup_worker(context: WorkerContext, stats: LoadStats) -> None:
    while context.created_directories:
        directory_id = context.created_directories.pop()
        deleted = await timed_call(
            stats,
            "cleanup_delete_directory",
            lambda directory_id=directory_id: context.client.delete_directory(
                directory_id
            ),
            include_in_total=False,
        )
        if deleted is not None and deleted.get("code") == 200:
            await timed_call(
                stats,
                "cleanup_purge_directory",
                lambda directory_id=directory_id: context.client.purge_directory(
                    directory_id
                ),
                include_in_total=False,
            )


def build_phases(args: argparse.Namespace) -> list[LoadPhase]:
    if args.arrival_pattern in {"closed", "fixed"}:
        return [LoadPhase(args.arrival_pattern, args.duration, args.rate)]
    if args.arrival_pattern == "step":
        phase_duration = args.duration / len(args.stage_rates)
        return [
            LoadPhase(f"step-{index + 1}", phase_duration, rate)
            for index, rate in enumerate(args.stage_rates)
        ]
    phases = []
    if args.spike_start > 0:
        phases.append(LoadPhase("pre-spike", args.spike_start, args.rate))
    phases.append(LoadPhase("spike", args.spike_duration, args.spike_rate))
    recovery = args.duration - args.spike_start - args.spike_duration
    if recovery > 0:
        phases.append(LoadPhase("recovery", recovery, args.rate))
    return phases


def _is_linked_worktree(repo_root: Path) -> bool:
    completed = subprocess.run(
        [
            "git",
            "rev-parse",
            "--path-format=absolute",
            "--git-dir",
            "--git-common-dir",
        ],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    paths = [Path(line).resolve() for line in completed.stdout.splitlines() if line]
    return len(paths) == 2 and paths[0] != paths[1]


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


def _git_commit(repo_root: Path) -> str | None:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip() or None


def _component_versions() -> dict[str, str]:
    components = {}
    for distribution in ("orjson", "pycryptodome", "websockets"):
        try:
            components[distribution] = version(distribution)
        except PackageNotFoundError:
            continue
    return components


async def server_metadata(
    client: CFMSTestClient,
    credentials: LoadCredentials | None,
    explicit_commit: str | None,
) -> dict:
    info = await client.server_info()
    data = info.get("data", {}) if info.get("code") == 200 else {}
    metadata = {
        "commit": explicit_commit,
        "protocol_version": data.get("protocol_version"),
    }
    if credentials is not None:
        diagnostics = await client.diagnostics()
        if diagnostics.get("code") == 200:
            diagnostic_data = diagnostics.get("data", {})
            metadata["version"] = diagnostic_data.get("server", {}).get("core_version")
            metadata["python_version"] = diagnostic_data.get("runtime", {}).get(
                "python_version"
            )
            components = diagnostic_data.get("component_versions")
            if isinstance(components, dict):
                metadata["component_versions"] = components
    return metadata


async def run_load(args: argparse.Namespace) -> dict:
    repo_root = Path(__file__).resolve().parents[2]
    src_dir = repo_root / "src"
    managed = args.host is None and args.port is None
    backup = None
    server = None
    contexts: list[WorkerContext] = []
    connection_stats = ConnectionStats()
    generator_health = GeneratorHealth()
    total = LoadStats()
    phase_results = []
    saturation_phase = None
    metadata_client: CFMSTestClient | None = None

    if managed:
        if not args.managed_reset:
            raise RuntimeError(
                "Managed mode deletes src/app.db and src/content/files; "
                "rerun in a disposable worktree with --managed-reset"
            )
        if not _is_linked_worktree(repo_root):
            raise RuntimeError(
                "Managed load tests require a disposable linked worktree"
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
        with TemporaryDirectory(prefix="cfms-load-") as payload_directory:
            payload_dir = Path(payload_directory)
            (payload_dir / "duplicate.bin").write_bytes(b"d" * args.payload_size)
            if args.scenario in {"connection-storm", "reconnect-storm"}:
                contexts = [
                    WorkerContext(
                        worker_id=worker_id,
                        client=CFMSTestClient(
                            host=settings.host,
                            port=settings.port,
                            use_ssl=settings.use_ssl,
                            ssl_context=ssl_context,
                        ),
                        credentials=None,
                        settings=settings,
                        ssl_context=ssl_context,
                        connection_stats=connection_stats,
                        payload_dir=payload_dir,
                    )
                    for worker_id in range(args.users)
                ]
                setup_stats = LoadStats()
                metadata_client = CFMSTestClient(
                    host=settings.host,
                    port=settings.port,
                    use_ssl=settings.use_ssl,
                    ssl_context=ssl_context,
                )
                if not await connect_client(metadata_client, connection_stats):
                    raise RuntimeError("Cannot connect for server metadata")
                metadata_credential = None
            else:
                contexts, setup_stats = await prepare_contexts(
                    settings,
                    args.users,
                    credentials,
                    ssl_context,
                    connection_stats,
                    payload_dir,
                )
                metadata_client = contexts[0].client
                metadata_credential = contexts[0].credentials
            total.merge(setup_stats)

            explicit_server_commit = args.server_commit
            if managed and explicit_server_commit is None:
                explicit_server_commit = _git_commit(repo_root)
            server_details = await server_metadata(
                metadata_client,
                metadata_credential,
                explicit_server_commit,
            )
            started_at = datetime.now(UTC)
            overall_start = time.perf_counter()
            stop_monitor = asyncio.Event()
            monitor_task = asyncio.create_task(
                monitor_generator(stop_monitor, generator_health)
            )
            scheduled_elapsed = 0.0
            try:
                for phase_index, phase in enumerate(build_phases(args)):
                    phase_start = time.perf_counter()
                    ramp_step = (
                        args.ramp_up / max(args.users - 1, 1) if phase_index == 0 else 0
                    )
                    worker_stats = await asyncio.gather(
                        *(
                            run_worker_phase(
                                context,
                                args,
                                phase,
                                phase_start,
                                ramp_step * context.worker_id,
                            )
                            for context in contexts
                        )
                    )
                    phase_elapsed = max(
                        time.perf_counter() - phase_start,
                        phase.duration_seconds,
                    )
                    scheduled_elapsed += phase.duration_seconds
                    phase_total = LoadStats()
                    for stats in worker_stats:
                        phase_total.merge(stats)
                        total.merge(stats)
                    phase_summary = summarize(
                        phase_total, phase_elapsed, args.scenario, args.users
                    )
                    phase_summary.update({"name": phase.name, "rate": phase.rate})
                    phase_results.append(phase_summary)
                    valid_outcomes = phase_total.total.successes + sum(
                        phase_total.total.expected_rejections.values()
                    )
                    if args.arrival_pattern == "step" and (
                        phase_total.dropped_iterations > 0
                        or (
                            phase_total.total.requests
                            and valid_outcomes / phase_total.total.requests < 0.99
                        )
                    ):
                        saturation_phase = phase.name
                        break
            finally:
                stop_monitor.set()
                await monitor_task
            elapsed = max(time.perf_counter() - overall_start, scheduled_elapsed)

            for context in contexts:
                if context.client.websocket is not None:
                    await cleanup_worker(context, total)
            if args.scenario in {"connection-storm", "reconnect-storm"}:
                await disconnect_client(metadata_client, connection_stats)

        return {
            "schema_version": 2,
            "profile": args.profile,
            **summarize(total, elapsed, args.scenario, args.users),
            "started_at": started_at.isoformat(),
            "finished_at": datetime.now(UTC).isoformat(),
            "random_seed": args.seed,
            "parameters": normalized_parameters(
                args, account_pool_size=max(1, len(credentials))
            ),
            "phases": phase_results,
            "saturation_phase": saturation_phase,
            "connections": connection_stats.summary(),
            "generator": generator_health.summary(),
            "harness": {
                "commit": args.harness_commit
                or os.environ.get("CFMS_HARNESS_COMMIT")
                or _git_commit(repo_root),
                "python_version": platform.python_version(),
                "python_implementation": platform.python_implementation(),
                "component_versions": _component_versions(),
            },
            "server": server_details,
            "target": {
                "config_id": args.target_id or "managed-disposable",
                "environment": args.target_environment or "managed-disposable",
            },
        }
    finally:
        if contexts:
            await asyncio.gather(
                *(
                    disconnect_client(context.client, connection_stats)
                    for context in contexts
                ),
                return_exceptions=True,
            )
        if metadata_client is not None and metadata_client not in [
            context.client for context in contexts
        ]:
            await disconnect_client(metadata_client, connection_stats)
        if server is not None:
            process, logs = server
            stop_server(process, logs)
        if backup is not None:
            restore_config(backup)


def _non_negative_duration(value: str) -> float:
    if value in {"0", "0s", "0ms"}:
        return 0.0
    return parse_duration(value)


def _positive_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be numeric") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="CFMS WebSocket load test tool")
    parser.add_argument("--profiles-file", type=Path, default=DEFAULT_PROFILE_PATH)
    parser.add_argument("--profile", default="smoke")
    parser.add_argument("--users", type=int)
    parser.add_argument("--duration", type=parse_duration)
    parser.add_argument("--ramp-up", type=_non_negative_duration)
    parser.add_argument("--rate", type=float)
    parser.add_argument(
        "--arrival-pattern", choices=["closed", "fixed", "step", "spike"]
    )
    parser.add_argument("--stage-rates", type=parse_stage_rates)
    parser.add_argument("--spike-rate", type=_positive_float)
    parser.add_argument("--spike-start", type=_non_negative_duration)
    parser.add_argument("--spike-duration", type=parse_duration)
    parser.add_argument("--scenario", choices=sorted(SCENARIOS))
    parser.add_argument("--inflight-per-user", type=int)
    parser.add_argument("--payload-size", type=int)
    parser.add_argument("--seed", type=int)
    parser.add_argument(
        "--action-weight",
        action="append",
        type=parse_action_weight,
        help="Override a mixed action weight, for example read=50",
    )
    parser.add_argument("--host")
    parser.add_argument("--port", type=int)
    parser.add_argument("--no-ssl", action="store_true")
    parser.add_argument("--tls-ca-file", type=Path)
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS verification only for an explicit disposable target",
    )
    parser.add_argument("--username")
    parser.add_argument("--password-env", default="CFMS_LOAD_PASSWORD")
    parser.add_argument("--accounts-file", type=Path)
    parser.add_argument("--target-id")
    parser.add_argument(
        "--target-environment",
        choices=["performance", "staging", "production"],
    )
    parser.add_argument("--allow-remote-mutations", action="store_true")
    parser.add_argument("--server-commit")
    parser.add_argument("--harness-commit")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--managed-reset", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--output", type=Path)
    return parser


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = build_parser()
    overrides = parser.parse_args(argv)
    if overrides.action_weight:
        overrides.action_weight = dict(overrides.action_weight)
    try:
        profiles = load_profiles(overrides.profiles_file)
        profile = profiles.get(overrides.profile)
        if profile is None:
            raise ValueError(
                f"unknown profile {overrides.profile!r}; available: "
                f"{', '.join(sorted(profiles))}"
            )
        if overrides.rate is not None and overrides.arrival_pattern is None:
            overrides.arrival_pattern = "fixed" if overrides.rate > 0 else "closed"
            overrides.stage_rates = ()
        if overrides.stage_rates is not None and overrides.arrival_pattern is None:
            overrides.arrival_pattern = "step"
            overrides.rate = 0
        args = apply_profile_overrides(profile, overrides)
    except ValueError as exc:
        parser.error(str(exc))
    remote = args.host is not None or args.port is not None
    if not remote:
        args.target_id = "managed-disposable"
        args.target_environment = "managed-disposable"
    if args.accounts_file is not None and (
        args.username is not None or args.password_env != "CFMS_LOAD_PASSWORD"
    ):
        parser.error("--accounts-file cannot be combined with single-account options")
    return args


def _write_result(path: Path, result: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def main() -> None:
    args = parse_args()
    result = asyncio.run(run_load(args))
    if args.output is not None:
        _write_result(args.output, result)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"Profile: {result['profile']}")
        print(f"Scenario: {result['scenario']}")
        print(f"Users: {result['users']}")
        print(f"Requests: {result['requests']}")
        print(f"Success rate: {result['success_rate']:.2%}")
        print(f"Valid outcome rate: {result['valid_outcome_rate']:.2%}")
        print(f"Throughput: {result['throughput_rps']} req/s")
        print(f"Dropped iterations: {result['dropped_iterations']}")
        print(f"Latency: {result['latency_ms']}")
        print(f"Errors: {result['errors']}")
        print(f"Expected rejections: {result['expected_rejections']}")
        print(f"Actions: {result['actions']}")


if __name__ == "__main__":
    main()
