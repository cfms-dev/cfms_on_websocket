import subprocess
import sys
from pathlib import Path

import pytest

from include.runtime_lock import (
    RuntimeLock,
    RuntimeLockError,
    server_runtime_lock,
)


def test_runtime_lock_rejects_a_second_process(tmp_path: Path) -> None:
    lock_path = tmp_path / "run" / "server.lock"
    script = (
        "import sys\n"
        "from include.runtime_lock import RuntimeLock, RuntimeLockError\n"
        "try:\n"
        "    RuntimeLock(sys.argv[1]).acquire()\n"
        "except RuntimeLockError:\n"
        "    raise SystemExit(23)\n"
        "raise SystemExit(0)\n"
    )

    with RuntimeLock(lock_path):
        result = subprocess.run(
            [sys.executable, "-c", script, str(lock_path)],
            check=False,
        )

    assert result.returncode == 23


def test_server_runtime_lock_rejects_unfinished_deployment(tmp_path: Path) -> None:
    transaction_path = tmp_path / ".maintenance" / "transaction.json"
    transaction_path.parent.mkdir()
    transaction_path.write_text("{}", encoding="utf-8")

    with pytest.raises(RuntimeLockError, match="must be recovered before startup"):
        server_runtime_lock(tmp_path)

    assert not (tmp_path / ".maintenance" / "server.lock").exists()


def test_server_runtime_lock_allows_deployment_recovery(tmp_path: Path) -> None:
    transaction_path = tmp_path / ".maintenance" / "transaction.json"
    transaction_path.parent.mkdir()
    transaction_path.write_text("{}", encoding="utf-8")

    with server_runtime_lock(tmp_path, allow_unfinished_deployment=True):
        assert (tmp_path / ".maintenance" / "server.lock").is_file()


def test_server_runtime_lock_blocks_maintenance_for_the_same_root(
    tmp_path: Path,
) -> None:
    with server_runtime_lock(tmp_path):
        with pytest.raises(RuntimeLockError):
            server_runtime_lock(tmp_path).acquire()
