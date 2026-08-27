from typing import Any

import jsonschema
from sqlalchemy.orm.session import object_session

from include.config.constants import AVAILABLE_ACCESS_TYPES
from include.database.models.access import CompiledAccessRuleSet
from include.database.models.documents import Document, Folder, Node
from include.database.models.identity import User
from include.domains.access.authorization.compiled_rules import (
    compile_access_rule,
)
from include.domains.access.authorization.evaluation import check_access_requirements

__all__ = [
    "apply_access_rules",
    "set_access_rules",
    "validate_access_rules",
]


ACCESS_RULE_SCHEMA = {
    "type": "array",
    "items": {
        "type": "object",
        "properties": {
            "match": {"enum": ["any", "all"]},
            "match_groups": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "match": {"enum": ["any", "all"]},
                        "rights": {
                            "type": "object",
                            "properties": {
                                "match": {"enum": ["any", "all"]},
                                "require": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                },
                            },
                            "additionalProperties": False,
                        },
                        "groups": {
                            "type": "object",
                            "properties": {
                                "match": {"enum": ["any", "all"]},
                                "require": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                },
                            },
                            "additionalProperties": False,
                        },
                    },
                    "additionalProperties": False,
                },
            },
        },
        "required": ["match", "match_groups"],
        "additionalProperties": False,
    },
}


def validate_access_rules(rules: list[dict[str, Any]]) -> None:
    """Validate access rules against the access-rule JSON schema."""
    jsonschema.validate(rules, ACCESS_RULE_SCHEMA)


def set_access_rules(
    target: Document | Folder,
    new_access_rules: dict[str, list[dict]],
    inherit_parent: bool = True,
) -> None:
    """Core helper: persist access rules for a Document or Folder without performing
    any user-permission checks. Only modifies the active transaction.

    Raises:
        ValueError: if an access type is unrecognised or rule data is null.
        TypeError: if ``target`` is neither a Document nor a Folder.
        RuntimeError: if ``target`` is not attached to a session.

    """
    session = object_session(target)
    if session is None:
        raise RuntimeError("Target must be attached to a session before setting rules")

    if target.id is None:
        session.flush()

    target_id = target.id
    assert target_id is not None, "Target must have an ID after flush"

    match target:
        case Document():
            target_type = "document"
        case Folder():
            target_type = "directory"
        case _:
            raise TypeError("Unsupported Object Type")

    compiled_rules = []

    for access_type, this_type_rules in new_access_rules.items():
        if access_type not in AVAILABLE_ACCESS_TYPES:
            raise ValueError(f"Invalid access type: {access_type}")

        if this_type_rules is None:
            raise ValueError(
                f"Access rule data for access type {access_type} can't be null"
            )

        # Use the JSON schema to validate the access rules before compiling them
        validate_access_rules(this_type_rules)

        for each_rule in this_type_rules:
            compiled_rule = compile_access_rule(
                access_type=access_type,
                rule_data=each_rule,
            )
            if compiled_rule is not None:
                compiled_rules.append(compiled_rule)

    # Use a SELECT ... FOR UPDATE to lock the target node and ensure that
    # no other transaction can modify its access rules concurrently.
    node_for_update = (
        session.query(Node)
        .filter(Node.id == target_id, Node.type == target_type)
        .with_for_update()
        .populate_existing()
        .one_or_none()
    )
    if node_for_update is None:
        raise RuntimeError("Target node no longer exists while setting access rules")

    old_rule_set_id = node_for_update.access_rule_set_id
    target.inherit = inherit_parent

    new_rule_set = None
    new_rule_set_id = None

    # Create a new CompiledAccessRuleSet if there are compiled rules to persist.
    if compiled_rules:
        new_rule_set = CompiledAccessRuleSet(node_id=target_id)
        new_rule_set.rules.extend(compiled_rules)
        session.add(new_rule_set)
        session.flush()
        new_rule_set_id = new_rule_set.id

    update_query = session.query(Node).filter(
        Node.id == target_id,
        Node.type == target_type,
    )

    # Optimistic locking update mechanism
    if old_rule_set_id is None:
        update_query = update_query.filter(Node.access_rule_set_id.is_(None))
    else:
        update_query = update_query.filter(Node.access_rule_set_id == old_rule_set_id)

    updated_count = update_query.update(
        {Node.access_rule_set_id: new_rule_set_id},
        synchronize_session="fetch",
    )
    if updated_count != 1:
        if new_rule_set is not None:
            session.delete(new_rule_set)
            session.flush()
        raise RuntimeError("Access rules changed concurrently; retry the operation")

    # Manually synchronize states of the ORM objects.
    node_for_update.access_rule_set = new_rule_set
    node_for_update.access_rule_set_id = new_rule_set_id
    target.access_rule_set = new_rule_set
    target.access_rule_set_id = new_rule_set_id
    session.flush()

    cleanup_query = session.query(CompiledAccessRuleSet).filter(
        CompiledAccessRuleSet.node_id == target_id
    )
    if new_rule_set_id is not None:
        cleanup_query = cleanup_query.filter(
            CompiledAccessRuleSet.id != new_rule_set_id
        )
    cleanup_query.delete(synchronize_session=False)


def apply_access_rules(
    target: Document | Folder,
    new_access_rules: dict[str, list[dict]],
    user: User,
    inherit_parent: bool = True,
) -> bool:
    """Attach access rules and verify the acting user still satisfies each rule.
    Only modifies the ORM object — does NOT commit.

    Returns False if any resulting rule would deny access to ``user``.
    """
    set_access_rules(target, new_access_rules, inherit_parent)
    session = object_session(target)
    if session is not None:
        session.flush()

    for access_type in new_access_rules:
        if not check_access_requirements(session, target, user, access_type):
            return False

    return True
