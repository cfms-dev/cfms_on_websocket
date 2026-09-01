"""Stable entry point for a versioned CFMS deployment."""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

_VERSION_PATTERN = re.compile(r"\d+\.\d+\.\d+").fullmatch


def main() -> None:
    deployment_root = Path(__file__).resolve().parent
    state_path = deployment_root / "deployment.json"
    if not state_path.is_file():
        return

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
        raise SystemExit(completed.returncode)
    os.execve(str(python), command, environment)


if __name__ == "__main__":
    main()
