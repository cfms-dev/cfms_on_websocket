import os
import socket
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from tomlkit import dumps, parse

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = PROJECT_ROOT / "src"
_TEST_ENVIRONMENT_NAMES = (
    "CFMS_TEST_HOST",
    "CFMS_TEST_PORT",
    "CFMS_TEST_USE_SSL",
)


@dataclass(frozen=True)
class ServerTestSettings:
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


def write_test_config(src_dir: Path, port: int) -> ServerTestSettings:
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
    return ServerTestSettings(
        host="::1",
        port=port,
        use_ssl=True,
        src_dir=src_dir,
        config_path=config_path,
    )


@contextmanager
def managed_test_config(
    src_dir: Path = SOURCE_ROOT,
) -> Generator[ServerTestSettings]:
    config_backup = capture_config(src_dir / "config.toml")
    old_environment = {name: os.environ.get(name) for name in _TEST_ENVIRONMENT_NAMES}

    try:
        settings = write_test_config(src_dir, reserve_local_port())
        os.environ["CFMS_TEST_HOST"] = settings.host
        os.environ["CFMS_TEST_PORT"] = str(settings.port)
        os.environ["CFMS_TEST_USE_SSL"] = "1" if settings.use_ssl else "0"
        yield settings
    finally:
        try:
            restore_config(config_backup)
        finally:
            for name, value in old_environment.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value
