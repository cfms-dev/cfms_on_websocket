import os
import ssl
import subprocess
import sys
import threading
import time
from contextlib import ExitStack
from pathlib import Path
from typing import IO

from websockets.exceptions import InvalidHandshake
from websockets.sync.client import connect

from tests.support.config import ServerTestSettings


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
        with ExitStack() as files:
            files.callback(self.stdout_file.close)
            files.callback(self.stderr_file.close)
            for thread in (self.stdout_thread, self.stderr_thread):
                if thread.ident is not None:
                    thread.join(timeout=2)


def log_server_output(
    process: subprocess.Popen, log_dir: str | Path = "test_logs"
) -> ServerLogCapture:
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    stdout_path = log_path / f"server_stdout_{timestamp}.log"
    stderr_path = log_path / f"server_stderr_{timestamp}.log"

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
                except ValueError, OSError:
                    break
        except ValueError, OSError:
            return

    with ExitStack() as files:
        stdout_file = files.enter_context(
            stdout_path.open("w", encoding="utf-8", buffering=1)
        )
        stderr_file = files.enter_context(
            stderr_path.open("w", encoding="utf-8", buffering=1)
        )
        stdout_thread = threading.Thread(
            target=read_stream, args=(process.stdout, stdout_file), daemon=True
        )
        stderr_thread = threading.Thread(
            target=read_stream, args=(process.stderr, stderr_file), daemon=True
        )
        logs = ServerLogCapture(
            stdout_thread, stderr_thread, stdout_file, stderr_file, stop_event
        )
        try:
            stdout_thread.start()
            stderr_thread.start()
        except BaseException:
            stop_server(process, logs)
            raise
        files.pop_all()
        return logs


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
    logs = None
    try:
        logs = log_server_output(
            process, Path("test_logs") / settings.src_dir.parent.name
        )
        password_path = settings.src_dir / "admin_password.txt"
        ssl_context = None
        if settings.use_ssl:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        host = f"[{settings.host}]" if ":" in settings.host else settings.host
        protocol = "wss" if settings.use_ssl else "ws"
        deadline = time.monotonic() + 20
        last_error = None
        while (remaining := deadline - time.monotonic()) > 0:
            if process.poll() is not None:
                raise RuntimeError(
                    f"Test server exited during startup: {process.returncode}"
                )
            if password_path.is_file():
                try:
                    with connect(
                        f"{protocol}://{host}:{settings.port}",
                        ssl=ssl_context,
                        proxy=None,
                        open_timeout=min(0.5, remaining),
                        close_timeout=1,
                    ):
                        return process, logs
                except (OSError, TimeoutError, InvalidHandshake) as exc:
                    last_error = exc
            time.sleep(min(0.05, remaining))
        raise RuntimeError(
            "Test server did not become ready within 20 seconds"
        ) from last_error
    except BaseException:
        stop_server(process, logs)
        raise


def stop_server(process: subprocess.Popen, logs: ServerLogCapture | None) -> None:
    with ExitStack() as resources:
        if logs is not None:
            resources.callback(logs.close)
        for pipe in (process.stdout, process.stderr):
            if pipe is not None:
                resources.callback(pipe.close)
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
