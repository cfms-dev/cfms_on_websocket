from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import insert

_PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _script_directory() -> ScriptDirectory:
    return ScriptDirectory.from_config(Config(_PROJECT_ROOT / "src" / "alembic.ini"))


def _seed_runtime_tables(base, source_engine) -> None:
    tables = base.metadata.tables
    with source_engine.begin() as connection:
        connection.execute(
            insert(tables["account_throttles"]),
            {
                "username": "alice",
                "factor": "password",
                "failed_attempts": 2,
                "last_attempt": 1_700_000_000.0,
                "locked_until": None,
            },
        )
        connection.execute(
            insert(tables["rate_limit_buckets"]),
            {
                "namespace": "request",
                "scope": "account",
                "identity": "alice",
                "tokens": 3.5,
                "last_refill_at": 1_700_000_000.0,
                "denial_count": 1,
                "last_denied_at": None,
                "last_attempt": 1_700_000_000.0,
            },
        )
        connection.execute(
            insert(tables["risk_ip_accounts"]),
            {
                "namespace": "request",
                "ip_address": "192.0.2.10",
                "username": "alice",
                "last_attempt": 1_700_000_000.0,
            },
        )
        connection.execute(
            insert(tables["file_deduplication_tasks"]),
            {
                "file_id": "file-doc",
                "phase": 0,
                "available_at": 1_700_000_000.0,
                "lease_owner": None,
                "lease_expires_at": None,
                "attempts": 0,
                "last_error": None,
                "created_time": 1_700_000_000.0,
            },
        )
