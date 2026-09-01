"""Stable entry point for a versioned CFMS deployment."""

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

_VERSION_PATTERN = re.compile(r"\d+\.\d+\.\d+").fullmatch


def _read_active_version(deployment_root: Path) -> str:
    state_path = deployment_root / "deployment.json"
    if not state_path.is_file():
        return ""

    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
        version = state["active_version"]
    except (
        KeyError,
        OSError,
        TypeError,
        UnicodeError,
        json.JSONDecodeError,
    ) as exc:
        raise SystemExit(f"Unable to read {state_path}: {exc}") from exc
    if not isinstance(version, str) or _VERSION_PATTERN(version) is None:
        raise SystemExit("deployment.json contains an invalid active version")
    return version


def _complete_pending_cleanup(deployment_root: Path, active_version: str) -> None:
    transaction_path = deployment_root / "shared" / "run" / "upgrade-transaction.json"
    if not transaction_path.exists():
        return
    try:
        transaction = json.loads(transaction_path.read_text(encoding="utf-8"))
        phase = transaction["phase"]
        from_version = transaction["from_version"]
        to_version = transaction["to_version"]
    except (
        KeyError,
        OSError,
        TypeError,
        UnicodeError,
        json.JSONDecodeError,
    ) as exc:
        raise SystemExit(
            f"Unfinished deployment transaction requires review: {transaction_path}"
        ) from exc
    if (
        phase not in {"activation", "cleanup-required"}
        or to_version != active_version
        or not isinstance(from_version, str)
        or _VERSION_PATTERN(from_version) is None
        or from_version == active_version
    ):
        raise SystemExit(
            f"Unfinished deployment transaction requires review: {transaction_path}"
        )
    retired_release = deployment_root / "releases" / from_version
    try:
        if retired_release.exists():
            shutil.rmtree(retired_release)
        transaction_path.unlink()
    except OSError as exc:
        raise SystemExit(
            f"Unable to remove inactive release {retired_release}: {exc}"
        ) from exc


def main() -> None:
    deployment_root = Path(__file__).resolve().parent
    version = _read_active_version(deployment_root)
    if not version:
        return
    _complete_pending_cleanup(deployment_root, version)

    release_root = deployment_root / "releases" / version
    if os.name == "nt":
        python = release_root / ".venv" / "Scripts" / "python.exe"
    else:
        python = release_root / ".venv" / "bin" / "python"
    if not python.is_file():
        raise SystemExit(f"Active release interpreter not found: {python}")

    arguments = sys.argv[1:]
    action = arguments[0] if arguments else "run"
    if action == "run":
        command = [str(python), str(release_root / "src" / "main.py"), *arguments[1:]]
    elif action == "maintain":
        command = [str(python), "-m", "maintenance.cli", *arguments[1:]]
    else:
        raise SystemExit("Usage: python main.py [run|maintain] [arguments ...]")

    environment = os.environ.copy()
    environment["CFMS_SERVER_ROOT"] = str(deployment_root / "shared")
    os.chdir(deployment_root / "shared")
    if os.name == "nt":
        completed = subprocess.run(command, env=environment, check=False)
        active_version = _read_active_version(deployment_root)
        _complete_pending_cleanup(deployment_root, active_version)
        raise SystemExit(completed.returncode)
    os.execve(str(python), command, environment)


if __name__ == "__main__":
    main()
