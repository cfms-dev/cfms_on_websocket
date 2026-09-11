import datetime as dt
import json
from io import StringIO
from pathlib import Path

import tomlkit
from rich.console import Console
from rich.progress import Progress
from sqlalchemy import create_engine, event, insert, select, update
from sqlalchemy.orm import sessionmaker

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_SRC_PATH = _PROJECT_ROOT / "src"


class _RootedStorage:
    def __init__(self, root: Path):
        self.root = root

    def _resolve(self, path: str) -> Path:
        return self.root.joinpath(*Path(path).parts)

    def fopen(self, path: str, mode: str = "rb"):
        resolved = self._resolve(path)
        if any(flag in mode for flag in ("w", "a", "+")):
            resolved.parent.mkdir(parents=True, exist_ok=True)
        return open(resolved, mode)

    def exists(self, path: str) -> bool:
        return self._resolve(path).exists()

    def remove(self, path: str) -> bool:
        resolved = self._resolve(path)
        if resolved.exists():
            resolved.unlink()
            return True
        return False

    def mkdir(self, path: str, mode: int = 0o777) -> None:
        self._resolve(path).mkdir(mode=mode)

    def makedirs(self, path: str, mode: int = 0o777, exist_ok: bool = False) -> None:
        self._resolve(path).mkdir(mode=mode, parents=True, exist_ok=exist_ok)

    def getsize(self, path: str) -> int:
        return self._resolve(path).stat().st_size


def _write_config(path: Path, *, secret_key: str, pepper: str) -> dict:
    sample = tomlkit.parse((_SRC_PATH / "config.toml.sample").read_text("utf-8"))
    sample["server"]["secret_key"] = secret_key
    sample["security"]["pepper"] = pepper
    sample["database"]["type"] = "sqlite"
    sample["database"]["file"] = str(path.with_suffix(".db"))
    sample["provider"]["storage"] = "local"
    sample["provider"]["caching"] = "memory"
    sample["provider"]["event_bus"] = "local"
    path.write_text(tomlkit.dumps(sample), encoding="utf-8")
    return sample


def _new_database(base, path: Path):
    db_engine = create_engine(f"sqlite:///{path}")

    @event.listens_for(db_engine, "connect")
    def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    base.metadata.create_all(db_engine)
    return db_engine, sessionmaker(bind=db_engine)


def _insert_compiled_rule(
    connection,
    tables,
    *,
    target_id: str,
    access_type: str,
    rule_data: dict,
) -> None:
    rule_set_id = connection.execute(
        select(tables["nodes"].c.access_rule_set_id).where(
            tables["nodes"].c.id == target_id
        )
    ).scalar_one()
    if rule_set_id is None:
        rule_set_id = f"rule-set-{target_id}"[:32]
        connection.execute(
            insert(tables["compiled_access_rule_sets"]),
            {
                "id": rule_set_id,
                "node_id": target_id,
                "created_at": 1_700_000_000.0,
            },
        )
        connection.execute(
            update(tables["nodes"])
            .where(tables["nodes"].c.id == target_id)
            .values(access_rule_set_id=rule_set_id)
        )

    result = connection.execute(
        insert(tables["compiled_access_rules"]),
        {
            "rule_set_id": rule_set_id,
            "access_type": access_type,
            "match_mode": rule_data.get("match", "all"),
        },
    )
    compiled_rule_id = result.inserted_primary_key[0]
    for index, group_data in enumerate(rule_data.get("match_groups", [])):
        rights = group_data.get("rights", {})
        groups = group_data.get("groups", {})
        required_rights = rights.get("require", [])
        required_groups = groups.get("require", [])
        rights_empty = "rights" not in group_data
        groups_empty = "groups" not in group_data
        group_result = connection.execute(
            insert(tables["compiled_access_rule_groups"]),
            {
                "rule_id": compiled_rule_id,
                "group_index": index,
                "match_mode": "all"
                if not required_rights or not required_groups
                else group_data.get("match", "all"),
                "rights_match_mode": rights.get("match", "all"),
                "rights_empty": rights_empty,
                "groups_match_mode": groups.get("match", "all"),
                "groups_empty": groups_empty,
            },
        )
        compiled_group_id = group_result.inserted_primary_key[0]
        for permission in required_rights:
            connection.execute(
                insert(tables["compiled_access_rule_rights"]),
                {"group_id": compiled_group_id, "permission": permission},
            )
        for group_name in required_groups:
            connection.execute(
                insert(tables["compiled_access_rule_memberships"]),
                {"group_id": compiled_group_id, "group_name": group_name},
            )


def _dump_backup_tables(base, db_engine) -> dict[str, list[dict]]:
    dumped = {}
    with db_engine.connect() as connection:
        for table_name in base.metadata.tables:
            if table_name not in _backup_table_names(base):
                continue
            table = base.metadata.tables[table_name]
            order_by = [column for column in table.primary_key.columns]
            statement = select(table)
            if order_by:
                statement = statement.order_by(*order_by)
            rows = []
            for row in connection.execute(statement).mappings():
                rows.append({key: _normalize(value) for key, value in row.items()})
            dumped[table_name] = rows
    return dumped


def _backup_table_names(base) -> set[str]:
    excluded = {
        "account_throttles",
        "file_tasks",
        "login_throttles",
        "rate_limit_buckets",
        "risk_ip_accounts",
        "schedule_executions",
        "scheduling_runtime_state",
        "system_states",
        "traffic_throttles",
    }
    return set(base.metadata.tables) - excluded


def _normalize(value):
    if isinstance(value, dt.datetime):
        return value.isoformat()
    return value


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(f"{json.dumps(row, separators=(',', ':'))}\n" for row in rows),
        encoding="utf-8",
    )


def _read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _test_progress() -> Progress:
    return Progress(
        console=Console(file=StringIO(), force_terminal=False, width=120),
    )
