import warnings
from dataclasses import dataclass

from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from alembic.script.revision import ResolutionError
from sqlalchemy import Engine, MetaData, inspect
from sqlalchemy.exc import SAWarning

from alembic import command
from include.config.paths import APPLICATION_ABSPATH

LEGACY_V0_7_REVISION = "7bddfba0d8aa"
LEGACY_V0_7_COLUMNS = {
    "account_throttles": {
        "factor",
        "failed_attempts",
        "last_attempt",
        "locked_until",
        "username",
    },
    "audit_entries": {
        "action",
        "data",
        "id",
        "logged_time",
        "remote_address",
        "result",
        "target",
        "username",
    },
    "banned_subnets": {
        "created_at",
        "expires_at",
        "reason_comment_id",
        "starts_at",
        "subnet",
    },
    "comments": {
        "comment_data",
        "comment_id",
        "comment_text",
        "content_digest",
        "digest_version",
    },
    "compiled_access_rule_groups": {
        "group_index",
        "groups_empty",
        "groups_match_mode",
        "id",
        "match_mode",
        "rights_empty",
        "rights_match_mode",
        "rule_id",
    },
    "compiled_access_rule_memberships": {"group_id", "group_name", "id"},
    "compiled_access_rule_rights": {"group_id", "id", "permission"},
    "compiled_access_rule_sets": {"created_at", "id", "node_id"},
    "compiled_access_rules": {"access_type", "id", "match_mode", "rule_set_id"},
    "document_metadata": {
        "creator_username",
        "document_id",
        "last_modified_by_username",
    },
    "document_metadata_tags": {"document_id", "position", "tag"},
    "document_revisions": {
        "created_time",
        "document_id",
        "file_id",
        "id",
        "parent_revision_id",
        "status",
    },
    "documents": {"created_time", "current_revision_id", "id"},
    "file_deduplication_tasks": {
        "attempts",
        "available_at",
        "created_time",
        "file_id",
        "last_error",
        "lease_expires_at",
        "lease_owner",
        "phase",
    },
    "file_tasks": {
        "chunk_size",
        "encryption_key",
        "end_time",
        "file_id",
        "id",
        "issued_by_username",
        "mode",
        "start_time",
        "status",
        "upload_checkpoint_data",
        "upload_checkpoint_size",
        "upload_file_size",
        "upload_session_id",
        "upload_sha256",
    },
    "files": {"active", "created_time", "id", "path", "sha256", "size"},
    "folders": {"created_time", "id"},
    "group_permissions": {
        "end_time",
        "granted",
        "group_name",
        "id",
        "permission",
        "start_time",
    },
    "keyrings": {"content", "created_time", "id", "label", "username"},
    "login_throttles": {
        "failed_attempts",
        "ip_address",
        "last_attempt",
        "locked_until",
        "username",
        "window_started_at",
    },
    "nodes": {
        "access_rule_set_id",
        "active_name",
        "id",
        "inherit",
        "name",
        "parent_id",
        "status",
        "status_operation_id",
        "type",
    },
    "object_access_entries": {
        "access_type",
        "end_time",
        "entity_identifier",
        "entity_type",
        "id",
        "start_time",
        "target_identifier",
        "target_type",
    },
    "rate_limit_buckets": {
        "denial_count",
        "identity",
        "last_attempt",
        "last_denied_at",
        "last_refill_at",
        "namespace",
        "scope",
        "tokens",
    },
    "risk_ip_accounts": {"ip_address", "last_attempt", "namespace", "username"},
    "system_states": {
        "owner",
        "payload",
        "revision",
        "schema_version",
        "state_key",
        "updated_at",
    },
    "traffic_throttles": {
        "failed_attempts",
        "ip_address",
        "last_attempt",
        "locked_until",
        "window_started_at",
    },
    "user_groups": {"group_display_name", "group_name"},
    "user_memberships": {"end_time", "group_name", "id", "start_time", "username"},
    "user_permissions": {
        "end_time",
        "granted",
        "id",
        "permission",
        "start_time",
        "username",
    },
    "userblock_entries": {
        "block_id",
        "not_after",
        "not_before",
        "reason_comment_id",
        "target_id",
        "target_type",
        "timestamp",
        "username",
    },
    "userblock_sub_entries": {"block_type", "id", "parent_id"},
    "users": {
        "avatar_id",
        "created_time",
        "last_login",
        "nickname",
        "pass_hash",
        "passwd_last_modified",
        "preference_dek_id",
        "secret_key",
        "status",
        "status_comment_id",
        "totp_backup_codes",
        "totp_enabled",
        "totp_secret",
        "username",
    },
}
LEGACY_V0_7_PRIMARY_KEYS = {
    "account_throttles": ("username", "factor"),
    "audit_entries": ("id",),
    "banned_subnets": ("subnet",),
    "comments": ("comment_id",),
    "compiled_access_rule_groups": ("id",),
    "compiled_access_rule_memberships": ("id",),
    "compiled_access_rule_rights": ("id",),
    "compiled_access_rule_sets": ("id",),
    "compiled_access_rules": ("id",),
    "document_metadata": ("document_id",),
    "document_metadata_tags": ("document_id", "tag"),
    "document_revisions": ("id",),
    "documents": ("id",),
    "file_deduplication_tasks": ("file_id",),
    "file_tasks": ("id",),
    "files": ("id",),
    "folders": ("id",),
    "group_permissions": ("id",),
    "keyrings": ("id",),
    "login_throttles": ("username", "ip_address"),
    "nodes": ("id",),
    "object_access_entries": ("id",),
    "rate_limit_buckets": ("namespace", "scope", "identity"),
    "risk_ip_accounts": ("namespace", "ip_address", "username"),
    "system_states": ("owner", "state_key"),
    "traffic_throttles": ("ip_address",),
    "user_groups": ("group_name",),
    "user_memberships": ("id",),
    "user_permissions": ("id",),
    "userblock_entries": ("block_id",),
    "userblock_sub_entries": ("id",),
    "users": ("username",),
}
LEGACY_V0_7_UNIQUE_CONSTRAINTS = {
    "comments": {frozenset(("digest_version", "content_digest"))},
    "nodes": {frozenset(("parent_id", "active_name"))},
    "users": {frozenset(("preference_dek_id",))},
}
LEGACY_V0_7_KEY_INDEXES = {
    "audit_entries": {("logged_time",)},
    "file_deduplication_tasks": {("available_at", "lease_expires_at")},
    "file_tasks": {
        ("file_id", "mode", "status"),
        ("mode", "status", "end_time"),
    },
    "files": {("sha256", "active", "created_time", "id")},
    "group_permissions": {("end_time", "id")},
    "user_permissions": {("end_time", "id")},
}


class DatabaseSchemaError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class SchemaUpgradeResult:
    previous_revision: str | None
    current_revision: str
    bootstrapped: bool
    adopted_legacy: bool


def _alembic_config(connection) -> tuple[Config, ScriptDirectory]:
    config_path = APPLICATION_ABSPATH / "alembic.ini"
    config = Config(config_path)
    config.attributes["connection"] = connection
    return config, ScriptDirectory.from_config(config)


def _application_schema(connection) -> dict[str, set[str]]:
    inspector = inspect(connection)
    return {
        table_name: {
            str(column["name"]) for column in inspector.get_columns(table_name)
        }
        for table_name in inspector.get_table_names()
        if table_name != "alembic_version"
    }


def _matches_legacy_schema(connection) -> bool:
    if _application_schema(connection) != LEGACY_V0_7_COLUMNS:
        return False
    inspector = inspect(connection)
    for table_name, expected in LEGACY_V0_7_PRIMARY_KEYS.items():
        primary_key = inspector.get_pk_constraint(table_name)
        if tuple(primary_key.get("constrained_columns") or ()) != expected:
            return False
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore",
            message="Skipped unsupported reflection of expression-based index.*",
            category=SAWarning,
        )
        for table_name, expected in LEGACY_V0_7_UNIQUE_CONSTRAINTS.items():
            actual = {
                frozenset(constraint.get("column_names") or ())
                for constraint in inspector.get_unique_constraints(table_name)
            }
            actual.update(
                frozenset(index.get("column_names") or ())
                for index in inspector.get_indexes(table_name)
                if index.get("unique")
            )
            if not expected.issubset(actual):
                return False
        for table_name, expected in LEGACY_V0_7_KEY_INDEXES.items():
            actual = {
                tuple(index.get("column_names") or ())
                for index in inspector.get_indexes(table_name)
            }
            if not expected.issubset(actual):
                return False
    return True


def _current_revision(connection) -> str | None:
    heads = MigrationContext.configure(connection).get_current_heads()
    if len(heads) > 1:
        raise DatabaseSchemaError(
            "Database has multiple Alembic heads: " + ", ".join(heads)
        )
    return heads[0] if heads else None


def upgrade_database_schema(
    engine: Engine,
    metadata: MetaData,
) -> SchemaUpgradeResult:
    if engine.dialect.name not in {"sqlite", "mysql"}:
        raise DatabaseSchemaError(
            "Schema upgrades support only SQLite and MySQL; "
            f"configured dialect is {engine.dialect.name!r}"
        )

    with engine.begin() as connection:
        config, scripts = _alembic_config(connection)
        target_heads = tuple(scripts.get_heads())
        if len(target_heads) != 1:
            raise DatabaseSchemaError(
                "The release must contain exactly one Alembic head"
            )
        target_revision = target_heads[0]
        previous_revision = _current_revision(connection)
        schema = _application_schema(connection)
        bootstrapped = False
        adopted_legacy = False

        if previous_revision is None and not schema:
            metadata.create_all(connection)
            command.stamp(config, target_revision)
            bootstrapped = True
        elif previous_revision is None:
            if not _matches_legacy_schema(connection):
                raise DatabaseSchemaError(
                    "Unversioned database does not match the supported v0.7.0 "
                    "schema; refusing to guess its migration revision"
                )
            try:
                scripts.get_revision(LEGACY_V0_7_REVISION)
            except ResolutionError as exc:
                raise DatabaseSchemaError(
                    "This release no longer contains the v0.7.0 adoption revision"
                ) from exc
            command.stamp(config, LEGACY_V0_7_REVISION)
            previous_revision = LEGACY_V0_7_REVISION
            adopted_legacy = True
            command.upgrade(config, target_revision)
        else:
            try:
                scripts.get_revision(previous_revision)
            except ResolutionError as exc:
                raise DatabaseSchemaError(
                    f"Database revision {previous_revision!r} is not present in "
                    "this release"
                ) from exc
            if previous_revision != target_revision:
                command.upgrade(config, target_revision)

        current_revision = _current_revision(connection)
        if current_revision != target_revision:
            raise DatabaseSchemaError(
                f"Database migration ended at {current_revision!r}; expected "
                f"{target_revision!r}"
            )

    return SchemaUpgradeResult(
        previous_revision=previous_revision,
        current_revision=target_revision,
        bootstrapped=bootstrapped,
        adopted_legacy=adopted_legacy,
    )


def verify_database_schema(engine: Engine) -> str:
    with engine.connect() as connection:
        _, scripts = _alembic_config(connection)
        target_heads = tuple(scripts.get_heads())
        if len(target_heads) != 1:
            raise DatabaseSchemaError(
                "The release must contain exactly one Alembic head"
            )
        revision = _current_revision(connection)
        if revision != target_heads[0]:
            rendered = revision or "unversioned"
            raise DatabaseSchemaError(
                f"Database schema is {rendered}; expected {target_heads[0]}. "
                "Stop the server and run 'maintain database upgrade'."
            )
        return revision
