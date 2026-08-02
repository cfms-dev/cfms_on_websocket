import importlib.util
from pathlib import Path

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import (
    JSON,
    BigInteger,
    Column,
    ForeignKey,
    Integer,
    MetaData,
    SmallInteger,
    String,
    Table,
    Text,
    UniqueConstraint,
    create_engine,
    event,
    inspect,
    select,
)


@pytest.fixture(autouse=True)
def _run_from_src(monkeypatch, protected_test_config) -> None:
    monkeypatch.chdir(protected_test_config.src_dir)


def _load_migration():
    path = Path("alembic/versions/5be1fb8b72af_store_comment_digests_as_binary.py")
    spec = importlib.util.spec_from_file_location("comment_digest_migration", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load comment digest migration")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _old_schema(engine):
    metadata = MetaData()
    comments = Table(
        "comments",
        metadata,
        Column(
            "comment_id", BigInteger().with_variant(Integer, "sqlite"), primary_key=True
        ),
        Column("digest_version", SmallInteger, nullable=False),
        Column("content_digest", String(64), nullable=False),
        Column("comment_text", Text, nullable=False),
        Column("comment_data", JSON),
        UniqueConstraint(
            "digest_version",
            "content_digest",
            name="uq_comments_content_digest",
        ),
    )
    users = Table(
        "users",
        metadata,
        Column("username", String(64), primary_key=True),
        Column(
            "status_comment_id",
            BigInteger().with_variant(Integer, "sqlite"),
            ForeignKey("comments.comment_id", ondelete="SET NULL"),
        ),
    )
    metadata.create_all(engine)
    return comments, users


def _migration_engine(tmp_path, name):
    engine = create_engine(f"sqlite:///{tmp_path / name}")

    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    return engine


def _run_migration(connection, migration, operation: str) -> None:
    context = MigrationContext.configure(connection)
    migration.op = Operations(context)
    getattr(migration, operation)()


def test_comment_digest_migration_round_trip_preserves_references(tmp_path) -> None:
    engine = _migration_engine(tmp_path, "round-trip.db")
    comments, users = _old_schema(engine)
    digest_hex = "ab" * 32
    with engine.begin() as connection:
        connection.execute(
            comments.insert(),
            {
                "comment_id": 7,
                "digest_version": 1,
                "content_digest": digest_hex,
                "comment_text": "Reason",
                "comment_data": {"ticket": 42},
            },
        )
        connection.execute(
            users.insert(),
            {"username": "alice", "status_comment_id": 7},
        )

    migration = _load_migration()
    with engine.begin() as connection:
        _run_migration(connection, migration, "upgrade")

    upgraded = MetaData()
    upgraded.reflect(engine)
    with engine.connect() as connection:
        row = connection.execute(select(upgraded.tables["comments"])).mappings().one()
        status_comment_id = connection.scalar(
            select(upgraded.tables["users"].c.status_comment_id)
        )
    assert row["content_digest"] == bytes.fromhex(digest_hex)
    assert status_comment_id == 7
    assert inspect(engine).get_unique_constraints("comments") == [
        {
            "name": "uq_comments_content_digest",
            "column_names": ["digest_version", "content_digest"],
        }
    ]

    with engine.begin() as connection:
        _run_migration(connection, migration, "downgrade")

    downgraded = MetaData()
    downgraded.reflect(engine)
    with engine.connect() as connection:
        row = connection.execute(select(downgraded.tables["comments"])).mappings().one()
        status_comment_id = connection.scalar(
            select(downgraded.tables["users"].c.status_comment_id)
        )
    assert row["content_digest"] == digest_hex
    assert status_comment_id == 7


@pytest.mark.parametrize("invalid_digest", ["not-a-digest", "a" * 63, "z" * 64])
def test_comment_digest_migration_rejects_invalid_hex(
    tmp_path,
    invalid_digest: str,
) -> None:
    engine = _migration_engine(tmp_path, f"invalid-{len(invalid_digest)}.db")
    comments, _users = _old_schema(engine)
    with engine.begin() as connection:
        connection.execute(
            comments.insert(),
            {
                "comment_id": 1,
                "digest_version": 1,
                "content_digest": invalid_digest,
                "comment_text": "Reason",
                "comment_data": None,
            },
        )

    migration = _load_migration()
    with (
        engine.begin() as connection,
        pytest.raises(RuntimeError, match="Invalid hexadecimal comment digest"),
    ):
        _run_migration(connection, migration, "upgrade")


def test_comment_digest_migration_rejects_binary_duplicates(tmp_path) -> None:
    engine = _migration_engine(tmp_path, "duplicate.db")
    comments, _users = _old_schema(engine)
    with engine.begin() as connection:
        connection.execute(
            comments.insert(),
            [
                {
                    "comment_id": 1,
                    "digest_version": 1,
                    "content_digest": "ab" * 32,
                    "comment_text": "Reason",
                    "comment_data": None,
                },
                {
                    "comment_id": 2,
                    "digest_version": 1,
                    "content_digest": "AB" * 32,
                    "comment_text": "Reason",
                    "comment_data": None,
                },
            ],
        )

    migration = _load_migration()
    with (
        engine.begin() as connection,
        pytest.raises(RuntimeError, match="Duplicate comment digest"),
    ):
        _run_migration(connection, migration, "upgrade")
