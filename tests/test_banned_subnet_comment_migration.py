import importlib.util
from pathlib import Path

from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import (
    BigInteger,
    Column,
    Double,
    Integer,
    LargeBinary,
    MetaData,
    SmallInteger,
    String,
    Table,
    Text,
    UniqueConstraint,
    create_engine,
    inspect,
    select,
)


def _load_migration():
    path = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "alembic"
        / "versions"
        / "18adc63ce5b1_reuse_comments_for_banned_subnet_reasons.py"
    )
    spec = importlib.util.spec_from_file_location(
        "banned_subnet_comment_migration", path
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _old_schema(metadata: MetaData) -> tuple[Table, Table]:
    comments = Table(
        "comments",
        metadata,
        Column(
            "comment_id",
            BigInteger().with_variant(Integer, "sqlite"),
            primary_key=True,
            autoincrement=True,
        ),
        Column("digest_version", SmallInteger, nullable=False),
        Column("content_digest", LargeBinary(32), nullable=False),
        Column("comment_text", Text, nullable=False),
        Column("comment_data", String),
        UniqueConstraint(
            "digest_version",
            "content_digest",
            name="uq_comments_content_digest",
        ),
    )
    banned_subnets = Table(
        "banned_subnets",
        metadata,
        Column("subnet", String(128), primary_key=True),
        Column("reason", String(255)),
        Column("created_at", Double, nullable=False),
        Column("starts_at", Double, nullable=False),
        Column("expires_at", Double),
    )
    return comments, banned_subnets


def _run(connection, migration, operation: str) -> None:
    context = MigrationContext.configure(
        connection,
        opts={
            "render_as_batch": True,
            "target_metadata": MetaData(
                naming_convention={
                    "fk": (
                        "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s"
                    ),
                    "pk": "pk_%(table_name)s",
                }
            ),
        },
    )
    operations = Operations(context)
    with operations.context(context):
        getattr(migration, operation)()


def test_banned_subnet_reason_migration_reuses_comments_and_round_trips(
    tmp_path,
) -> None:
    migration = _load_migration()
    engine = create_engine(f"sqlite:///{tmp_path / 'migration.db'}")
    metadata = MetaData()
    comments, banned_subnets = _old_schema(metadata)
    metadata.create_all(engine)
    serialized = migration._serialize("shared incident")

    with engine.begin() as connection:
        connection.execute(
            comments.insert(),
            {
                "comment_id": 1,
                "digest_version": migration.DIGEST_VERSION,
                "content_digest": migration._content_digest(serialized),
                "comment_text": "shared incident",
                "comment_data": None,
            },
        )
        connection.execute(
            banned_subnets.insert(),
            [
                {
                    "subnet": "192.0.2.0/24",
                    "reason": "shared incident",
                    "created_at": 1.0,
                    "starts_at": 1.0,
                },
                {
                    "subnet": "198.51.100.0/24",
                    "reason": "shared incident",
                    "created_at": 2.0,
                    "starts_at": 2.0,
                },
                {
                    "subnet": "203.0.113.0/24",
                    "reason": "another incident",
                    "created_at": 3.0,
                    "starts_at": 3.0,
                },
                {
                    "subnet": "2001:db8::/32",
                    "reason": None,
                    "created_at": 4.0,
                    "starts_at": 4.0,
                },
            ],
        )

        _run(connection, migration, "upgrade")

        upgraded = MetaData()
        upgraded.reflect(connection)
        subnet_rows = connection.execute(
            select(upgraded.tables["banned_subnets"]).order_by(
                upgraded.tables["banned_subnets"].c.created_at
            )
        ).mappings()
        assert [row["reason_comment_id"] for row in subnet_rows] == [1, 1, 2, None]
        assert len(connection.execute(select(upgraded.tables["comments"])).all()) == 2
        assert "reason" not in {
            column["name"]
            for column in inspect(connection).get_columns("banned_subnets")
        }
        foreign_keys = inspect(connection).get_foreign_keys("banned_subnets")
        assert foreign_keys[0]["constrained_columns"] == ["reason_comment_id"]
        assert foreign_keys[0]["referred_table"] == "comments"

        _run(connection, migration, "downgrade")

        downgraded = MetaData()
        downgraded.reflect(connection)
        subnet_rows = connection.execute(
            select(downgraded.tables["banned_subnets"]).order_by(
                downgraded.tables["banned_subnets"].c.created_at
            )
        ).mappings()
        assert [row["reason"] for row in subnet_rows] == [
            "shared incident",
            "shared incident",
            "another incident",
            None,
        ]

    engine.dispose()
