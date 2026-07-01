"""document metadata

Revision ID: a50674184a2c
Revises: cb1df1f5c488
Create Date: 2026-06-16 09:44:17.857205

"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a50674184a2c'
down_revision: str | Sequence[str] | None = 'cb1df1f5c488'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _has_fk(
    inspector: sa.engine.reflection.Inspector, table_name: str, column_name: str
) -> bool:
    return any(
        fk.get("constrained_columns") == [column_name]
        for fk in inspector.get_foreign_keys(table_name)
    )


def _has_index(
    inspector: sa.engine.reflection.Inspector, table_name: str, index_name: str
) -> bool:
    return any(
        index.get("name") == index_name for index in inspector.get_indexes(table_name)
    )


def upgrade() -> None:
    """Upgrade schema."""
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    if not inspector.has_table("document_metadata"):
        op.create_table(
            "document_metadata",
            sa.Column("document_id", sa.VARCHAR(length=255), nullable=False),
            sa.Column("creator_username", sa.VARCHAR(length=64), nullable=True),
            sa.Column(
                "last_modified_by_username", sa.VARCHAR(length=64), nullable=True
            ),
            sa.ForeignKeyConstraint(
                ["creator_username"],
                ["users.username"],
                name=op.f("fk_document_metadata_creator_username_users"),
                ondelete="SET NULL",
            ),
            sa.ForeignKeyConstraint(
                ["document_id"],
                ["documents.id"],
                name=op.f("fk_document_metadata_document_id_documents"),
                ondelete="CASCADE",
            ),
            sa.ForeignKeyConstraint(
                ["last_modified_by_username"],
                ["users.username"],
                name=op.f("fk_document_metadata_last_modified_by_username_users"),
                ondelete="SET NULL",
            ),
            sa.PrimaryKeyConstraint("document_id", name=op.f("pk_document_metadata")),
        )
        op.create_index(
            op.f("ix_document_metadata_creator_username"),
            "document_metadata",
            ["creator_username"],
            unique=False,
        )
        op.create_index(
            op.f("ix_document_metadata_last_modified_by_username"),
            "document_metadata",
            ["last_modified_by_username"],
            unique=False,
        )
    else:
        column_names = {
            column["name"] for column in inspector.get_columns("document_metadata")
        }
        document_id_column = next(
            (
                column
                for column in inspector.get_columns("document_metadata")
                if column["name"] == "document_id"
            ),
            None,
        )
        with op.batch_alter_table("document_metadata", schema=None) as batch_op:
            if document_id_column is not None:
                batch_op.alter_column(
                    "document_id",
                    existing_type=document_id_column["type"],
                    type_=sa.VARCHAR(length=255),
                    existing_nullable=False,
                )
            if "creator_username" not in column_names:
                batch_op.add_column(
                    sa.Column(
                        "creator_username", sa.VARCHAR(length=64), nullable=True
                    )
                )
            if "last_modified_by_username" not in column_names:
                batch_op.add_column(
                    sa.Column(
                        "last_modified_by_username",
                        sa.VARCHAR(length=64),
                        nullable=True,
                    )
                )
            if not _has_fk(inspector, "document_metadata", "document_id"):
                batch_op.create_foreign_key(
                    op.f("fk_document_metadata_document_id_documents"),
                    "documents",
                    ["document_id"],
                    ["id"],
                    ondelete="CASCADE",
                )
            if not _has_fk(inspector, "document_metadata", "creator_username"):
                batch_op.create_foreign_key(
                    op.f("fk_document_metadata_creator_username_users"),
                    "users",
                    ["creator_username"],
                    ["username"],
                    ondelete="SET NULL",
                )
            if not _has_fk(
                inspector, "document_metadata", "last_modified_by_username"
            ):
                batch_op.create_foreign_key(
                    op.f("fk_document_metadata_last_modified_by_username_users"),
                    "users",
                    ["last_modified_by_username"],
                    ["username"],
                    ondelete="SET NULL",
                )

        inspector = sa.inspect(conn)
        if not _has_index(
            inspector,
            "document_metadata",
            op.f("ix_document_metadata_creator_username"),
        ):
            op.create_index(
                op.f("ix_document_metadata_creator_username"),
                "document_metadata",
                ["creator_username"],
                unique=False,
            )
        if not _has_index(
            inspector,
            "document_metadata",
            op.f("ix_document_metadata_last_modified_by_username"),
        ):
            op.create_index(
                op.f("ix_document_metadata_last_modified_by_username"),
                "document_metadata",
                ["last_modified_by_username"],
                unique=False,
            )

    inspector = sa.inspect(conn)
    if not inspector.has_table("document_metadata_tags"):
        op.create_table(
            "document_metadata_tags",
            sa.Column("document_id", sa.VARCHAR(length=255), nullable=False),
            sa.Column("tag", sa.VARCHAR(length=255), nullable=False),
            sa.Column("position", sa.Integer(), nullable=False),
            sa.ForeignKeyConstraint(
                ["document_id"],
                ["document_metadata.document_id"],
                name=op.f("fk_document_metadata_tags_document_id_document_metadata"),
                ondelete="CASCADE",
            ),
            sa.PrimaryKeyConstraint(
                "document_id", "tag", name=op.f("pk_document_metadata_tags")
            ),
        )

    inspector = sa.inspect(conn)
    if not _has_index(
        inspector, "document_metadata_tags", op.f("ix_document_metadata_tags_tag")
    ):
        op.create_index(
            op.f("ix_document_metadata_tags_tag"),
            "document_metadata_tags",
            ["tag"],
            unique=False,
        )

    op.execute(
        """
        INSERT INTO document_metadata (document_id)
        SELECT id
        FROM documents
        WHERE NOT EXISTS (
            SELECT 1
            FROM document_metadata
            WHERE document_metadata.document_id = documents.id
        )
        """
    )

    user_groups = sa.table("user_groups", sa.column("group_name", sa.String()))
    group_permissions = sa.table(
        "group_permissions",
        sa.column("group_name", sa.String()),
        sa.column("permission", sa.String()),
        sa.column("granted", sa.Boolean()),
        sa.column("start_time", sa.Float()),
        sa.column("end_time", sa.Float()),
    )

    sysop_exists = conn.execute(
        sa.select(user_groups.c.group_name).where(user_groups.c.group_name == "sysop")
    ).first()
    if sysop_exists:
        for permission in ("view_metadata", "set_metadata_tags"):
            permission_exists = conn.execute(
                sa.select(group_permissions.c.permission).where(
                    group_permissions.c.group_name == "sysop",
                    group_permissions.c.permission == permission,
                    group_permissions.c.granted == True,
                )
            ).first()
            if not permission_exists:
                conn.execute(
                    group_permissions.insert().values(
                        group_name="sysop",
                        permission=permission,
                        granted=True,
                        start_time=0.0,
                        end_time=None,
                    )
                )


def downgrade() -> None:
    """Downgrade schema."""
    conn = op.get_bind()
    group_permissions = sa.table(
        "group_permissions",
        sa.column("group_name", sa.String()),
        sa.column("permission", sa.String()),
    )
    conn.execute(
        group_permissions.delete().where(
            group_permissions.c.group_name == "sysop",
            group_permissions.c.permission.in_(["view_metadata", "set_metadata_tags"]),
        )
    )

    op.drop_index(
        op.f("ix_document_metadata_tags_tag"), table_name="document_metadata_tags"
    )
    op.drop_table("document_metadata_tags")
    op.drop_index(
        op.f("ix_document_metadata_last_modified_by_username"),
        table_name="document_metadata",
    )
    op.drop_index(
        op.f("ix_document_metadata_creator_username"), table_name="document_metadata"
    )
    op.drop_table("document_metadata")
