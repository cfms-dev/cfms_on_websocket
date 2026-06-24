from __future__ import annotations

import os
import socket
from dataclasses import dataclass
from pathlib import Path

from tomlkit import dumps, parse


@dataclass(frozen=True)
class TestServerSettings:
    host: str
    port: int
    use_ssl: bool
    src_dir: Path
    config_path: Path


@dataclass(frozen=True)
class ConfigBackup:
    path: Path
    original_bytes: bytes | None


def reserve_local_port() -> int:
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
        sock.bind(("::1", 0))
        return int(sock.getsockname()[1])


def capture_config(config_path: Path) -> ConfigBackup:
    if config_path.exists():
        return ConfigBackup(config_path, config_path.read_bytes())
    return ConfigBackup(config_path, None)


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    with open(tmp_path, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, path)


def restore_config(backup: ConfigBackup) -> None:
    if backup.original_bytes is None:
        if backup.path.exists():
            backup.path.unlink()
        return
    atomic_write(backup.path, backup.original_bytes)


def write_test_config(src_dir: Path, port: int) -> TestServerSettings:
    config_path = src_dir / "config.toml"
    sample_path = src_dir / "config.toml.sample"

    if sample_path.exists():
        base_content = sample_path.read_text(encoding="utf-8")
    elif config_path.exists():
        base_content = config_path.read_text(encoding="utf-8")
    else:
        raise RuntimeError("Config sample file not found: src/config.toml.sample")

    config = parse(base_content)
    config["debug"] = True
    config["server"]["host"] = "::1"
    config["server"]["port"] = port
    config["server"]["dualstack_ipv6"] = False
    config["security"]["enable_passwd_force_expiration"] = False
    config["security"]["require_passwd_enforcement_changes"] = False
    config["security"]["require_client_cert"] = False
    config["database"]["type"] = "sqlite"
    config["database"]["file"] = "app.db"
    config["provider"]["storage"] = "local"
    config["provider"]["caching"] = "memory"
    config["provider"]["event_bus"] = "local"

    atomic_write(config_path, dumps(config).encode("utf-8"))
    return TestServerSettings(
        host="::1",
        port=port,
        use_ssl=True,
        src_dir=src_dir,
        config_path=config_path,
    )
