from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import IO

from tests.support.test_config import ServerTestSettings


class ServerLogCapture:
    def __init__(
        self,
        stdout_thread: threading.Thread,
        stderr_thread: threading.Thread,
        stdout_file: IO[str],
        stderr_file: IO[str],
        stop_event: threading.Event,
    ) -> None:
        self.stdout_thread = stdout_thread
        self.stderr_thread = stderr_thread
        self.stdout_file = stdout_file
        self.stderr_file = stderr_file
        self.stop_event = stop_event

    def close(self) -> None:
        self.stop_event.set()
        self.stdout_thread.join(timeout=2)
        self.stderr_thread.join(timeout=2)
        self.stdout_file.close()
        self.stderr_file.close()


def log_server_output(
    process: subprocess.Popen, log_dir: str | Path = "test_logs"
) -> ServerLogCapture:
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    stdout_path = log_path / f"server_stdout_{timestamp}.log"
    stderr_path = log_path / f"server_stderr_{timestamp}.log"

    stdout_file = open(stdout_path, "w", encoding="utf-8", buffering=1)
    stderr_file = open(stderr_path, "w", encoding="utf-8", buffering=1)
    stop_event = threading.Event()

    def read_stream(stream, output_file):
        try:
            while not stop_event.is_set():
                line = stream.readline()
                if not line:
                    break
                try:
                    output_file.write(line)
                    output_file.flush()
                except (ValueError, OSError):
                    break
        except Exception:
            pass

    stdout_thread = threading.Thread(
        target=read_stream, args=(process.stdout, stdout_file), daemon=True
    )
    stderr_thread = threading.Thread(
        target=read_stream, args=(process.stderr, stderr_file), daemon=True
    )
    stdout_thread.start()
    stderr_thread.start()

    return ServerLogCapture(
        stdout_thread,
        stderr_thread,
        stdout_file,
        stderr_file,
        stop_event,
    )


def start_server(
    settings: ServerTestSettings,
) -> tuple[subprocess.Popen, ServerLogCapture]:
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["CFMS_TEST_HOST"] = settings.host
    env["CFMS_TEST_PORT"] = str(settings.port)
    env["CFMS_TEST_USE_SSL"] = "1" if settings.use_ssl else "0"

    process = subprocess.Popen(
        [sys.executable, "main.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        bufsize=1,
        cwd=settings.src_dir,
        env=env,
    )
    logs = log_server_output(process)

    password_path = settings.src_dir / "admin_password.txt"
    max_wait = 20
    waited = 0.0
    while waited < max_wait:
        time.sleep(0.5)
        waited += 0.5
        if process.poll() is not None:
            break
        if password_path.exists():
            time.sleep(1)
            break

    if not password_path.exists():
        stop_server(process, logs)
        raise RuntimeError(
            f"Server initialization timed out or crashed after {max_wait}s."
        )

    return process, logs


def stop_server(process: subprocess.Popen, logs: ServerLogCapture) -> None:
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)

    for pipe in (process.stdout, process.stderr):
        try:
            if pipe:
                pipe.close()
        except Exception:
            pass
    logs.close()
