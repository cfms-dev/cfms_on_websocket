from __future__ import annotations

from typing import Any, Iterable, Literal

from sqlalchemy import delete, event
from sqlalchemy.orm import Session as OrmSession

from include.database.models.access import (
    CompiledAccessRule,
    CompiledAccessRuleGroup,
    CompiledAccessRuleMembership,
    CompiledAccessRuleRight,
)
from include.database.session import Session

TargetType = Literal["document", "directory"]

_PENDING_TARGETS_KEY = "compiled_access_rule_pending_targets"
_DELETED_TARGET_KEYS = "compiled_access_rule_deleted_target_keys"


def mark_access_rules_for_compilation(target: Any) -> None:
    setattr(target, "_compile_access_rules_after_flush", True)


def _target_type_and_id(target: Any) -> tuple[TargetType, str] | None:
    from include.database.models.documents import Document, Folder

    if isinstance(target, Document) and target.id:
        return "document", target.id
    if isinstance(target, Folder) and target.id:
        return "directory", target.id
    return None


def _tracked_document_target(target: Any) -> bool:
    from include.database.models.documents import Document, Folder

    return isinstance(target, (Document, Folder))


def _as_match_mode(value: Any) -> str:
    return value if value in ("all", "any") else "all"


def _require_list(group_data: dict[str, Any], key: str) -> list[str]:
    value = group_data.get(key, {})
    if not isinstance(value, dict):
        return []
    required = value.get("require", [])
    if not isinstance(required, list):
        return []
    return [str(item) for item in required]


def _compile_match_groups(
    rule_data: dict[str, Any],
) -> Iterable[CompiledAccessRuleGroup]:
    match_groups = rule_data.get("match_groups", [])
    if not isinstance(match_groups, list):
        return []

    compiled_groups: list[CompiledAccessRuleGroup] = []
    for index, group_data in enumerate(match_groups):
        if not isinstance(group_data, dict) or not group_data:
            continue

        rights_group = group_data.get("rights", {})
        if not isinstance(rights_group, dict):
            rights_group = {}
        groups_group = group_data.get("groups", {})
        if not isinstance(groups_group, dict):
            groups_group = {}

        required_rights = _require_list(group_data, "rights")
        required_groups = _require_list(group_data, "groups")
        rights_empty = not required_rights
        groups_empty = not required_groups
        match_mode = _as_match_mode(group_data.get("match", "all"))
        if rights_empty or groups_empty:
            match_mode = "all"

        compiled_group = CompiledAccessRuleGroup(
            group_index=index,
            match_mode=match_mode,
            rights_match_mode=_as_match_mode(rights_group.get("match", "all")),
            rights_empty=rights_empty,
            groups_match_mode=_as_match_mode(groups_group.get("match", "all")),
            groups_empty=groups_empty,
        )
        compiled_group.rights.extend(
            CompiledAccessRuleRight(permission=permission)
            for permission in required_rights
        )
        compiled_group.groups.extend(
            CompiledAccessRuleMembership(group_name=group_name)
            for group_name in required_groups
        )
        compiled_groups.append(compiled_group)

    return compiled_groups


def compile_access_rule(
    *,
    target_type: TargetType,
    target_id: str,
    source_rule_id: int,
    access_type: str,
    rule_data: dict[str, Any],
) -> CompiledAccessRule | None:
    if not rule_data:
        return None

    compiled_rule = CompiledAccessRule(
        target_type=target_type,
        target_id=target_id,
        source_rule_id=source_rule_id,
        access_type=access_type,
        match_mode=_as_match_mode(rule_data.get("match", "all")),
    )
    compiled_rule.match_groups.extend(_compile_match_groups(rule_data))
    return compiled_rule


def rebuild_compiled_access_rules(
    session: OrmSession,
    target: Any,
) -> None:
    target_key = _target_type_and_id(target)
    if target_key is None:
        return
    target_type, target_id = target_key

    session.execute(
        delete(CompiledAccessRule).where(
            CompiledAccessRule.target_type == target_type,
            CompiledAccessRule.target_id == target_id,
        )
    )

    for rule in target.access_rules:
        compiled_rule = compile_access_rule(
            target_type=target_type,
            target_id=target_id,
            source_rule_id=rule.id,
            access_type=rule.access_type,
            rule_data=rule.rule_data,
        )
        if compiled_rule is not None:
            session.add(compiled_rule)


def delete_compiled_access_rules(
    session: OrmSession,
    target_type: TargetType,
    target_id: str,
) -> None:
    session.execute(
        delete(CompiledAccessRule).where(
            CompiledAccessRule.target_type == target_type,
            CompiledAccessRule.target_id == target_id,
        )
    )


@event.listens_for(Session, "before_flush")
def _collect_access_rule_targets(session: OrmSession, *_args) -> None:
    pending = session.info.setdefault(_PENDING_TARGETS_KEY, [])
    for target in list(session.new) + list(session.dirty):
        if getattr(target, "_compile_access_rules_after_flush", False):
            pending.append(target)
            setattr(target, "_compile_access_rules_after_flush", False)

    deleted_keys = session.info.setdefault(_DELETED_TARGET_KEYS, set())
    for target in session.deleted:
        if _tracked_document_target(target):
            target_key = _target_type_and_id(target)
            if target_key is not None:
                deleted_keys.add(target_key)


@event.listens_for(Session, "after_flush_postexec")
def _sync_compiled_access_rules(session: OrmSession, *_args) -> None:
    deleted_keys = session.info.pop(_DELETED_TARGET_KEYS, set())
    for target_type, target_id in deleted_keys:
        delete_compiled_access_rules(session, target_type, target_id)

    pending_targets = session.info.pop(_PENDING_TARGETS_KEY, [])
    seen: set[tuple[TargetType, str]] = set()
    for target in pending_targets:
        target_key = _target_type_and_id(target)
        if target_key is None or target_key in deleted_keys or target_key in seen:
            continue
        seen.add(target_key)
        rebuild_compiled_access_rules(session, target)
