import json
import os
from pathlib import Path
from typing import BinaryIO, Self

import portalocker


class RuntimeLockError(RuntimeError):
    pass


class RuntimeLock:
    def __init__(self, path: str | Path, *, shared: bool = False):
        self.path = Path(path)
        self.shared = shared
        self._file: BinaryIO | None = None

    def acquire(self) -> Self:
        if self._file is not None:
            raise RuntimeError("Runtime lock is already acquired")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock_file = self.path.open("a+b")
        try:
            if lock_file.seek(0, os.SEEK_END) == 0:
                lock_file.write(b"\0")
                lock_file.flush()
            lock_file.seek(0)
            mode = (
                portalocker.LockFlags.SHARED
                if self.shared
                else portalocker.LockFlags.EXCLUSIVE
            )
            portalocker.lock(
                lock_file,
                mode | portalocker.LockFlags.NON_BLOCKING,
            )
        except (OSError, portalocker.LockException) as exc:
            lock_file.close()
            raise RuntimeLockError(
                f"CFMS server is already using runtime root {self.path.parent.parent}"
            ) from exc

        self._file = lock_file
        if not self.shared:
            metadata = json.dumps(
                {"pid": os.getpid()},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            lock_file.seek(0)
            lock_file.truncate()
            lock_file.write(metadata)
            lock_file.flush()
        return self

    def release(self) -> None:
        lock_file = self._file
        if lock_file is None:
            return
        try:
            lock_file.seek(0)
            portalocker.unlock(lock_file)
        finally:
            lock_file.close()
            self._file = None

    def __enter__(self) -> Self:
        return self.acquire()

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.release()


def server_runtime_lock(
    server_root: str | Path,
    *,
    allow_unfinished_deployment: bool = False,
) -> RuntimeLock:
    maintenance_root = Path(server_root) / ".maintenance"
    transaction_path = maintenance_root / "transaction.json"
    if transaction_path.exists() and not allow_unfinished_deployment:
        raise RuntimeLockError(
            "An unfinished deployment transaction must be recovered before startup: "
            f"{transaction_path}"
        )
    return RuntimeLock(maintenance_root / "server.lock")


def jobs_runtime_lock(
    server_root: str | Path,
    *,
    allow_unfinished_deployment: bool = False,
) -> RuntimeLock:
    maintenance_root = Path(server_root) / ".maintenance"
    transaction_path = maintenance_root / "transaction.json"
    if transaction_path.exists() and not allow_unfinished_deployment:
        raise RuntimeLockError(
            "An unfinished deployment transaction must be recovered before startup: "
            f"{transaction_path}"
        )
    return RuntimeLock(maintenance_root / "jobs.lock", shared=True)


class DeploymentRuntimeLock:
    def __init__(
        self, server_root: str | Path, *, allow_unfinished_deployment: bool = False
    ):
        maintenance_root = Path(server_root) / ".maintenance"
        self._server = server_runtime_lock(
            server_root,
            allow_unfinished_deployment=allow_unfinished_deployment,
        )
        self._jobs = RuntimeLock(maintenance_root / "jobs.lock")

    def acquire(self) -> Self:
        self._server.acquire()
        try:
            self._jobs.acquire()
        except Exception:
            self._server.release()
            raise
        return self

    def release(self) -> None:
        try:
            self._jobs.release()
        finally:
            self._server.release()

    def __enter__(self) -> Self:
        return self.acquire()

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.release()


def deployment_runtime_lock(
    server_root: str | Path,
    *,
    allow_unfinished_deployment: bool = False,
) -> DeploymentRuntimeLock:
    return DeploymentRuntimeLock(
        server_root,
        allow_unfinished_deployment=allow_unfinished_deployment,
    )
