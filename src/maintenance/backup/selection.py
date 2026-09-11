import enum
from collections.abc import Iterable
from dataclasses import dataclass

from sqlalchemy import Table, exists, or_, select

from include.database.models.access import (
    CompiledAccessRule,
    CompiledAccessRuleGroup,
    CompiledAccessRuleMembership,
    CompiledAccessRuleRight,
    CompiledAccessRuleSet,
    ObjectAccessEntry,
    UserBlockEntry,
    UserBlockSubEntry,
)
from include.database.models.documents import (
    Document,
    DocumentMetadata,
    DocumentMetadataTag,
    DocumentRevision,
    Folder,
)
from include.database.models.files import File
from include.database.models.identity import (
    User,
    UserGroup,
    UserGroupPermission,
    UserMembership,
    UserPermission,
)
from include.database.models.keyrings import UserKey
from include.database.models.operations import AuditEntry
from include.database.models.security import BannedSubnet
from include.database.session import Base
from maintenance.backup.models import BackupFormatError

_MODEL_IMPORTS = (
    UserBlockEntry,
    UserBlockSubEntry,
    AuditEntry,
    ObjectAccessEntry,
    CompiledAccessRule,
    CompiledAccessRuleGroup,
    CompiledAccessRuleMembership,
    CompiledAccessRuleRight,
    CompiledAccessRuleSet,
    User,
    UserGroup,
    UserGroupPermission,
    UserMembership,
    UserPermission,
    Document,
    DocumentMetadata,
    DocumentMetadataTag,
    DocumentRevision,
    Folder,
    File,
    UserKey,
    BannedSubnet,
)


BACKUP_TABLE_NAMES = (
    "files",
    "comments",
    "users",
    "user_groups",
    "group_permissions",
    "user_memberships",
    "user_permissions",
    "keyrings",
    "nodes",
    "folders",
    "documents",
    "document_revisions",
    "document_metadata",
    "document_metadata_tags",
    "object_access_entries",
    "compiled_access_rule_sets",
    "compiled_access_rules",
    "compiled_access_rule_groups",
    "compiled_access_rule_memberships",
    "compiled_access_rule_rights",
    "audit_entries",
    "userblock_entries",
    "userblock_sub_entries",
    "banned_subnets",
    "schedules",
)


EXCLUDED_TABLE_NAMES = frozenset(
    {
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
)


INSERT_ORDER = (
    "files",
    "comments",
    "users",
    "user_groups",
    "group_permissions",
    "user_memberships",
    "user_permissions",
    "keyrings",
    "nodes",
    "folders",
    "documents",
    "document_revisions",
    "document_metadata",
    "document_metadata_tags",
    "object_access_entries",
    "compiled_access_rule_sets",
    "compiled_access_rules",
    "compiled_access_rule_groups",
    "compiled_access_rule_memberships",
    "compiled_access_rule_rights",
    "audit_entries",
    "userblock_entries",
    "userblock_sub_entries",
    "banned_subnets",
    "schedules",
)


class BackupComponent(enum.StrEnum):
    ACCOUNTS = "accounts"
    DOCUMENT_LIBRARY = "documents"
    AUDIT_LOG = "audit"
    BANNED_SUBNETS = "banned_subnets"
    CONFIGURATION = "configuration"


BACKUP_COMPONENT_TABLES: dict[BackupComponent, tuple[str, ...]] = {
    BackupComponent.ACCOUNTS: (
        "comments",
        "users",
        "user_groups",
        "group_permissions",
        "user_memberships",
        "user_permissions",
        "keyrings",
        "userblock_entries",
        "userblock_sub_entries",
        "schedules",
    ),
    BackupComponent.DOCUMENT_LIBRARY: (
        "nodes",
        "folders",
        "documents",
        "document_revisions",
        "document_metadata",
        "document_metadata_tags",
        "object_access_entries",
        "compiled_access_rule_sets",
        "compiled_access_rules",
        "compiled_access_rule_groups",
        "compiled_access_rule_memberships",
        "compiled_access_rule_rights",
    ),
    BackupComponent.AUDIT_LOG: ("audit_entries",),
    BackupComponent.BANNED_SUBNETS: ("comments", "banned_subnets"),
    BackupComponent.CONFIGURATION: (),
}


BACKUP_COMPONENT_DEPENDENCIES: dict[BackupComponent, tuple[BackupComponent, ...]] = {
    BackupComponent.DOCUMENT_LIBRARY: (BackupComponent.ACCOUNTS,),
    BackupComponent.AUDIT_LOG: (BackupComponent.ACCOUNTS,),
}


DOCUMENT_ACCESS_TARGET_TYPES = frozenset({"document", "directory"})


COMPILED_ACCESS_RULE_TABLE_NAMES = frozenset(
    {
        "compiled_access_rules",
        "compiled_access_rule_sets",
        "compiled_access_rule_groups",
        "compiled_access_rule_memberships",
        "compiled_access_rule_rights",
    }
)


LEGACY_ACCESS_RULE_TABLE_NAMES = frozenset(
    {
        "document_access_rules",
        "folder_access_rules",
    }
)


@dataclass(frozen=True)
class BackupExportSelection:
    components: frozenset[BackupComponent]

    def __post_init__(self) -> None:
        normalized = frozenset(
            _coerce_backup_component(item) for item in self.components
        )
        if not normalized:
            raise ValueError("Choose at least one backup component")
        object.__setattr__(self, "components", normalized)

    @classmethod
    def from_component_values(
        cls,
        values: Iterable[BackupComponent | str],
    ) -> BackupExportSelection:
        return cls(frozenset(_coerce_backup_component(value) for value in values))

    @classmethod
    def full(cls) -> BackupExportSelection:
        return cls(frozenset(BackupComponent))

    def resolved_components(self) -> frozenset[BackupComponent]:
        return _resolve_component_dependencies(self.components)


def _coerce_backup_component(value: BackupComponent | str) -> BackupComponent:
    if isinstance(value, BackupComponent):
        return value
    try:
        return BackupComponent(value)
    except ValueError as exc:
        allowed = ", ".join(component.value for component in BackupComponent)
        raise ValueError(
            f"Unknown backup component {value!r}; choose from {allowed}"
        ) from exc


def _selection_components(
    selection: BackupExportSelection | None,
) -> frozenset[BackupComponent]:
    if selection is None:
        return frozenset(BackupComponent)
    return selection.resolved_components()


def _resolve_component_dependencies(
    components: Iterable[BackupComponent],
) -> frozenset[BackupComponent]:
    resolved = set(components)
    changed = True
    while changed:
        changed = False
        for component in tuple(resolved):
            for dependency in BACKUP_COMPONENT_DEPENDENCIES.get(component, ()):
                if dependency not in resolved:
                    resolved.add(dependency)
                    changed = True
    return frozenset(resolved)


def _selected_table_names(
    components: frozenset[BackupComponent],
    *,
    include_files: bool,
) -> tuple[str, ...]:
    selected = set()
    for component in components:
        selected.update(BACKUP_COMPONENT_TABLES[component])
    if include_files:
        selected.add("files")
    return tuple(
        table_name for table_name in BACKUP_TABLE_NAMES if table_name in selected
    )


def _collect_selected_file_ids(
    connection,
    tables: dict[str, Table],
    components: frozenset[BackupComponent],
) -> frozenset[str]:
    file_ids: set[str] = set()
    if BackupComponent.ACCOUNTS in components:
        users = tables["users"]
        statement = select(users.c.avatar_id).where(users.c.avatar_id.is_not(None))
        for row in connection.execute(statement):
            file_ids.add(str(row[0]))

    if BackupComponent.DOCUMENT_LIBRARY in components:
        revisions = tables["document_revisions"]
        statement = select(revisions.c.file_id).where(revisions.c.file_id.is_not(None))
        for row in connection.execute(statement):
            file_ids.add(str(row[0]))

    return frozenset(file_ids)


def _collect_active_compiled_rule_set_ids(
    connection,
    tables: dict[str, Table],
) -> frozenset[str]:
    nodes = tables["nodes"]
    rule_sets = tables["compiled_access_rule_sets"]
    rules = tables["compiled_access_rules"]
    statement = (
        select(rule_sets.c.id)
        .join(nodes, nodes.c.access_rule_set_id == rule_sets.c.id)
        .where(
            rule_sets.c.node_id == nodes.c.id,
            exists(select(1).where(rules.c.rule_set_id == rule_sets.c.id)),
        )
        .order_by(rule_sets.c.id)
    )
    return frozenset(str(row[0]) for row in connection.execute(statement))


def _apply_export_table_filter(
    statement,
    table: Table,
    table_name: str,
    tables: dict[str, Table],
    components: frozenset[BackupComponent],
    file_ids: frozenset[str],
):
    if table_name == "files":
        return statement.where(table.c.id.in_(sorted(file_ids)))
    if (
        table_name == "object_access_entries"
        and BackupComponent.DOCUMENT_LIBRARY in components
    ):
        return statement.where(
            table.c.target_type.in_(sorted(DOCUMENT_ACCESS_TARGET_TYPES))
        )
    if table_name == "comments":
        reference_filters = []
        if BackupComponent.ACCOUNTS in components:
            users = tables["users"]
            user_blocks = tables["userblock_entries"]
            reference_filters.append(
                table.c.comment_id.in_(
                    select(users.c.status_comment_id).where(
                        users.c.status_comment_id.is_not(None)
                    )
                )
            )
            reference_filters.append(
                table.c.comment_id.in_(
                    select(user_blocks.c.reason_comment_id).where(
                        user_blocks.c.reason_comment_id.is_not(None)
                    )
                )
            )
        if BackupComponent.BANNED_SUBNETS in components:
            banned_subnets = tables["banned_subnets"]
            reference_filters.append(
                table.c.comment_id.in_(
                    select(banned_subnets.c.reason_comment_id).where(
                        banned_subnets.c.reason_comment_id.is_not(None)
                    )
                )
            )
        return statement.where(or_(*reference_filters))
    return statement


def _apply_compiled_access_rule_export_filter(
    statement,
    table: Table,
    table_name: str,
    tables: dict[str, Table],
    active_compiled_rule_set_ids: frozenset[str],
):
    if table_name == "compiled_access_rule_sets":
        return statement.where(table.c.id.in_(sorted(active_compiled_rule_set_ids)))
    if table_name == "compiled_access_rules":
        return statement.where(
            table.c.rule_set_id.in_(sorted(active_compiled_rule_set_ids))
        )
    if table_name == "compiled_access_rule_groups":
        rules = tables["compiled_access_rules"]
        return statement.where(
            table.c.rule_id.in_(
                select(rules.c.id).where(
                    rules.c.rule_set_id.in_(sorted(active_compiled_rule_set_ids))
                )
            )
        )
    if table_name in {
        "compiled_access_rule_memberships",
        "compiled_access_rule_rights",
    }:
        rules = tables["compiled_access_rules"]
        groups = tables["compiled_access_rule_groups"]
        return statement.where(
            table.c.group_id.in_(
                select(groups.c.id).where(
                    groups.c.rule_id.in_(
                        select(rules.c.id).where(
                            rules.c.rule_set_id.in_(
                                sorted(active_compiled_rule_set_ids)
                            )
                        )
                    )
                )
            )
        )
    return statement


def _backup_tables() -> dict[str, Table]:
    missing = [name for name in BACKUP_TABLE_NAMES if name not in Base.metadata.tables]
    if missing:
        raise BackupFormatError(f"Backup table metadata is missing: {missing}")
    return {name: Base.metadata.tables[name] for name in BACKUP_TABLE_NAMES}
