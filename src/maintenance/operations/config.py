import secrets
from dataclasses import dataclass
from pathlib import Path

import tomlkit

from maintenance.operations.exceptions import MaintenanceOperationError
from maintenance.runtime import ensure_src_workdir


@dataclass(frozen=True)
class PepperFillResult:
    config_path: Path
    changed: bool
    added_security_section: bool


def fill_pepper(config_path: str | Path = "config.toml") -> PepperFillResult:
    ensure_src_workdir()
    path = Path(config_path)
    if not path.exists():
        raise MaintenanceOperationError(f"Configuration file not found: {path}")

    try:
        doc = tomlkit.parse(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise MaintenanceOperationError(f"Unable to read {path}: {exc}") from exc

    added_security_section = False
    if "security" not in doc:
        doc.add("security", tomlkit.table())
        added_security_section = True

    security_section = doc["security"]
    if security_section.get("pepper"):
        return PepperFillResult(
            config_path=path,
            changed=False,
            added_security_section=added_security_section,
        )

    security_section["pepper"] = secrets.token_hex(32)
    try:
        path.write_text(tomlkit.dumps(doc), encoding="utf-8")
    except Exception as exc:
        raise MaintenanceOperationError(f"Unable to write {path}: {exc}") from exc

    return PepperFillResult(
        config_path=path,
        changed=True,
        added_security_section=added_security_section,
    )
