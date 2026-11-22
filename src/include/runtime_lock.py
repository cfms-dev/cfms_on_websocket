import json
import os
from pathlib import Path
from typing import BinaryIO, Self

if os.name == "nt":
    import msvcrt
else:
    import fcntl


class RuntimeLockError(RuntimeError):
    pass


class RuntimeLock:
    def __init__(self, path: str | Path):
        self.path = Path(path)
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
            if os.name == "nt":
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            lock_file.close()
            raise RuntimeLockError(
                f"CFMS server is already using runtime root {self.path.parent.parent}"
            ) from exc

        self._file = lock_file
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
            if os.name == "nt":
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        finally:
            lock_file.close()
            self._file = None

    def __enter__(self) -> Self:
        return self.acquire()

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.release()


def server_runtime_lock(server_root: str | Path) -> RuntimeLock:
    maintenance_root = Path(server_root) / ".maintenance"
    transaction_path = maintenance_root / "transaction.json"
    if transaction_path.exists():
        raise RuntimeLockError(
            "An unfinished deployment transaction must be recovered before startup: "
            f"{transaction_path}"
        )
    return RuntimeLock(maintenance_root / "server.lock")
