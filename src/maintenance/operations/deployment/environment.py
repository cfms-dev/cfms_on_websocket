import os
import shutil
import subprocess
from pathlib import Path

from maintenance.operations.deployment.models import DeploymentSettings
from maintenance.operations.deployment.repository import _maintenance_root
from maintenance.operations.exceptions import MaintenanceOperationError


def _run(command_line: list[str], *, cwd: Path) -> None:
    # Callers construct uv argv sequences; no argument is interpreted by a shell.
    result = subprocess.run(  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
        command_line,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
        shell=False,
    )
    if result.returncode:
        output = "\n".join(
            part.strip() for part in (result.stdout, result.stderr) if part.strip()
        )
        raise MaintenanceOperationError(
            f"Command failed with exit code {result.returncode}: "
            + " ".join(command_line)
            + (f"\n{output}" if output else "")
        )


def _sync_environment(project_root: Path, settings: DeploymentSettings) -> None:
    uv = shutil.which("uv")
    if uv is None:
        raise MaintenanceOperationError("uv is required to switch a release")
    command_line = [
        uv,
        "sync",
        "--project",
        str(project_root),
        "--locked",
        "--no-dev",
    ]
    for extra in settings.extras:
        command_line.extend(("--extra", extra))
    _run(command_line, cwd=project_root)
    requirements = _maintenance_root(project_root) / "requirements.lock"
    if requirements.is_file() and requirements.stat().st_size:
        python = (
            project_root / ".venv" / "Scripts" / "python.exe"
            if os.name == "nt"
            else project_root / ".venv" / "bin" / "python"
        )
        _run(
            [
                uv,
                "pip",
                "install",
                "--python",
                str(python),
                "--requirements",
                str(requirements),
                "--require-hashes",
                "--strict",
            ],
            cwd=project_root,
        )
