"""make compiled access rules authoritative

Revision ID: 6684e3c18160
Revises: b8adfe3864ff
Create Date: 2026-07-02 10:19:56.460572

"""

import json
from typing import Any, Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "6684e3c18160"
down_revision: Union[str, Sequence[str], None] = "b8adfe3864ff"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    _clear_compiled_access_rules()

    with op.batch_alter_table("compiled_access_rules", schema=None) as batch_op:
        batch_op.drop_constraint(
            "uq_compiled_access_rules_target_source",
            type_="unique",
        )
        batch_op.drop_column("source_rule_id")

    _backfill_from_legacy_access_rules()

    op.drop_table("document_access_rules")
    op.drop_table("folder_access_rules")


def downgrade() -> None:
    """Downgrade schema."""
    op.create_table(
        "folder_access_rules",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("access_type", sa.VARCHAR(length=64), nullable=False),
        sa.Column("folder_id", sa.VARCHAR(length=255), nullable=True),
        sa.Column("rule_data", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(
            ["folder_id"],
            ["folders.id"],
            name=op.f("fk_folder_access_rules_folder_id_folders"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_folder_access_rules")),
    )
    op.create_table(
        "document_access_rules",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("access_type", sa.VARCHAR(length=64), nullable=False),
        sa.Column("document_id", sa.VARCHAR(length=255), nullable=False),
        sa.Column("rule_data", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(
            ["document_id"],
            ["documents.id"],
            name=op.f("fk_document_access_rules_document_id_documents"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_document_access_rules")),
    )
    with op.batch_alter_table("compiled_access_rules", schema=None) as batch_op:
        batch_op.add_column(sa.Column("source_rule_id", sa.Integer(), nullable=True))

    _restore_legacy_access_rules_from_compiled()

    with op.batch_alter_table("compiled_access_rules", schema=None) as batch_op:
        batch_op.alter_column(
            "source_rule_id",
            existing_type=sa.Integer(),
            nullable=False,
        )
        batch_op.create_unique_constraint(
            "uq_compiled_access_rules_target_source",
            ["target_type", "source_rule_id"],
        )


def _as_match_mode(value: Any) -> str:
    return value if value in ("all", "any") else "all"


def _parse_rule_data(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _required_items(group_data: dict[str, Any], key: str) -> list[str]:
    value = group_data.get(key, {})
    if not isinstance(value, dict):
        return []
    required = value.get("require", [])
    if not isinstance(required, list):
        return []
    return [str(item) for item in required]


def _compiled_tables():
    metadata = sa.MetaData()
    rules_table = sa.Table(
        "compiled_access_rules",
        metadata,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_type", sa.String()),
        sa.Column("target_id", sa.String()),
        sa.Column("access_type", sa.String()),
        sa.Column("match_mode", sa.String()),
    )
    groups_table = sa.Table(
        "compiled_access_rule_groups",
        metadata,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("rule_id", sa.Integer()),
        sa.Column("group_index", sa.Integer()),
        sa.Column("match_mode", sa.String()),
        sa.Column("rights_match_mode", sa.String()),
        sa.Column("rights_empty", sa.Boolean()),
        sa.Column("groups_match_mode", sa.String()),
        sa.Column("groups_empty", sa.Boolean()),
    )
    rights_table = sa.Table(
        "compiled_access_rule_rights",
        metadata,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("group_id", sa.Integer()),
        sa.Column("permission", sa.String()),
    )
    memberships_table = sa.Table(
        "compiled_access_rule_memberships",
        metadata,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("group_id", sa.Integer()),
        sa.Column("group_name", sa.String()),
    )
    return rules_table, groups_table, rights_table, memberships_table


def _clear_compiled_access_rules() -> None:
    conn = op.get_bind()
    rules_table, groups_table, rights_table, memberships_table = _compiled_tables()
    conn.execute(sa.delete(memberships_table))
    conn.execute(sa.delete(rights_table))
    conn.execute(sa.delete(groups_table))
    conn.execute(sa.delete(rules_table))


def _backfill_one_rule(
    conn,
    *,
    rules_table,
    groups_table,
    rights_table,
    memberships_table,
    target_type: str,
    target_id: str | None,
    access_type: str,
    rule_data: dict[str, Any],
) -> None:
    if not target_id or not rule_data:
        return

    result = conn.execute(
        rules_table.insert().values(
            target_type=target_type,
            target_id=target_id,
            access_type=access_type,
            match_mode=_as_match_mode(rule_data.get("match", "all")),
        )
    )
    compiled_rule_id = result.inserted_primary_key[0]

    match_groups = rule_data.get("match_groups", [])
    if not isinstance(match_groups, list):
        return

    for index, group_data in enumerate(match_groups):
        if not isinstance(group_data, dict) or not group_data:
            continue

        rights_group = group_data.get("rights", {})
        if not isinstance(rights_group, dict):
            rights_group = {}
        groups_group = group_data.get("groups", {})
        if not isinstance(groups_group, dict):
            groups_group = {}

        required_rights = _required_items(group_data, "rights")
        required_groups = _required_items(group_data, "groups")
        rights_empty = not required_rights
        groups_empty = not required_groups
        match_mode = _as_match_mode(group_data.get("match", "all"))
        if rights_empty or groups_empty:
            match_mode = "all"

        result = conn.execute(
            groups_table.insert().values(
                rule_id=compiled_rule_id,
                group_index=index,
                match_mode=match_mode,
                rights_match_mode=_as_match_mode(rights_group.get("match", "all")),
                rights_empty=rights_empty,
                groups_match_mode=_as_match_mode(groups_group.get("match", "all")),
                groups_empty=groups_empty,
            )
        )
        compiled_group_id = result.inserted_primary_key[0]
        for permission in required_rights:
            conn.execute(
                rights_table.insert().values(
                    group_id=compiled_group_id,
                    permission=permission,
                )
            )
        for group_name in required_groups:
            conn.execute(
                memberships_table.insert().values(
                    group_id=compiled_group_id,
                    group_name=group_name,
                )
            )


def _backfill_from_legacy_access_rules() -> None:
    conn = op.get_bind()
    rules_table, groups_table, rights_table, memberships_table = _compiled_tables()
    document_rules = sa.table(
        "document_access_rules",
        sa.column("id", sa.Integer),
        sa.column("document_id", sa.String),
        sa.column("access_type", sa.String),
        sa.column("rule_data", sa.JSON),
    )
    folder_rules = sa.table(
        "folder_access_rules",
        sa.column("id", sa.Integer),
        sa.column("folder_id", sa.String),
        sa.column("access_type", sa.String),
        sa.column("rule_data", sa.JSON),
    )

    for row in conn.execute(sa.select(document_rules).order_by(document_rules.c.id)):
        _backfill_one_rule(
            conn,
            rules_table=rules_table,
            groups_table=groups_table,
            rights_table=rights_table,
            memberships_table=memberships_table,
            target_type="document",
            target_id=row.document_id,
            access_type=row.access_type,
            rule_data=_parse_rule_data(row.rule_data),
        )

    for row in conn.execute(sa.select(folder_rules).order_by(folder_rules.c.id)):
        _backfill_one_rule(
            conn,
            rules_table=rules_table,
            groups_table=groups_table,
            rights_table=rights_table,
            memberships_table=memberships_table,
            target_type="directory",
            target_id=row.folder_id,
            access_type=row.access_type,
            rule_data=_parse_rule_data(row.rule_data),
        )


def _serialize_compiled_rule(
    conn,
    rule,
    *,
    groups_table,
    rights_table,
    memberships_table,
) -> dict[str, Any]:
    match_groups: list[dict[str, Any]] = []
    groups = conn.execute(
        sa.select(groups_table)
        .where(groups_table.c.rule_id == rule.id)
        .order_by(groups_table.c.group_index)
    )
    for group in groups:
        rights = [
            right.permission
            for right in conn.execute(
                sa.select(rights_table)
                .where(rights_table.c.group_id == group.id)
                .order_by(rights_table.c.id)
            )
        ]
        memberships = [
            membership.group_name
            for membership in conn.execute(
                sa.select(memberships_table)
                .where(memberships_table.c.group_id == group.id)
                .order_by(memberships_table.c.id)
            )
        ]
        group_data: dict[str, Any] = {}
        if not group.rights_empty:
            group_data["rights"] = {
                "match": group.rights_match_mode,
                "require": rights,
            }
        if not group.groups_empty:
            group_data["groups"] = {
                "match": group.groups_match_mode,
                "require": memberships,
            }
        if not group.rights_empty and not group.groups_empty:
            group_data["match"] = group.match_mode
        match_groups.append(group_data)
    return {"match": rule.match_mode, "match_groups": match_groups}


def _restore_legacy_access_rules_from_compiled() -> None:
    conn = op.get_bind()
    rules_table, groups_table, rights_table, memberships_table = _compiled_tables()
    compiled_rules_with_source = sa.table(
        "compiled_access_rules",
        sa.column("id", sa.Integer),
        sa.column("target_type", sa.String),
        sa.column("target_id", sa.String),
        sa.column("access_type", sa.String),
        sa.column("match_mode", sa.String),
        sa.column("source_rule_id", sa.Integer),
    )
    metadata = sa.MetaData()
    document_rules = sa.Table(
        "document_access_rules",
        metadata,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("document_id", sa.String()),
        sa.Column("access_type", sa.String()),
        sa.Column("rule_data", sa.JSON()),
    )
    folder_rules = sa.Table(
        "folder_access_rules",
        metadata,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("folder_id", sa.String()),
        sa.Column("access_type", sa.String()),
        sa.Column("rule_data", sa.JSON()),
    )

    for rule in conn.execute(sa.select(rules_table).order_by(rules_table.c.id)):
        rule_data = _serialize_compiled_rule(
            conn,
            rule,
            groups_table=groups_table,
            rights_table=rights_table,
            memberships_table=memberships_table,
        )
        if rule.target_type == "document":
            result = conn.execute(
                document_rules.insert().values(
                    document_id=rule.target_id,
                    access_type=rule.access_type,
                    rule_data=rule_data,
                )
            )
        elif rule.target_type == "directory":
            result = conn.execute(
                folder_rules.insert().values(
                    folder_id=rule.target_id,
                    access_type=rule.access_type,
                    rule_data=rule_data,
                )
            )
        else:
            continue

        source_rule_id = result.inserted_primary_key[0]
        conn.execute(
            compiled_rules_with_source.update()
            .where(compiled_rules_with_source.c.id == rule.id)
            .values(source_rule_id=source_rule_id)
        )
