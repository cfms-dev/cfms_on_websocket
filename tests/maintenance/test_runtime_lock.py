import subprocess
import sys
from pathlib import Path

from include.runtime_lock import RuntimeLock


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
