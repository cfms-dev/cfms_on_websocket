from __future__ import annotations

from typing import TYPE_CHECKING, Any

import jsonschema
from sqlalchemy.orm.session import object_session

from include.config.constants import AVAILABLE_ACCESS_TYPES
from include.database.models.access import CompiledAccessRuleSet
from include.database.models.identity import User

if TYPE_CHECKING:
    from include.database.models.documents import Document, Folder

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
                        "rights": {
                            "type": "object",
                            "properties": {
                                "match": {"enum": ["any", "all"]},
                                "require": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                },
                            },
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
                        },
                    },
                },
            },
        },
        "required": ["match", "match_groups"],
    },
}


def validate_access_rules(rules: list[dict[str, Any]]) -> None:
    jsonschema.validate(rules, ACCESS_RULE_SCHEMA)


def set_access_rules(
    target: Document | Folder,
    new_access_rules: dict[str, list[dict]],
    inherit_parent: bool = True,
) -> None:
    """
    Core helper: persist access rules for a Document or Folder without performing
    any user-permission checks. Only modifies the active transaction.

    Raises:
        ValueError: if an access type is unrecognised or rule data is null.
        TypeError: if ``target`` is neither a Document nor a Folder.
        RuntimeError: if ``target`` is not attached to a session.
    """
    from include.domains.access.authorization.compiled_rules import (
        _target_type_and_id,
        compile_access_rule,
    )

    session = object_session(target)
    if session is None:
        raise RuntimeError("Target must be attached to a session before setting rules")

    target.inherit = inherit_parent
    session.flush()
    target_key = _target_type_and_id(target)
    if target_key is None:
        raise TypeError("Unsupported Object Type")
    target_type, target_id = target_key

    compiled_rules = []

    for access_type, this_type_rules in new_access_rules.items():
        if access_type not in AVAILABLE_ACCESS_TYPES:
            raise ValueError(f"Invalid access type: {access_type}")

        if this_type_rules is None:
            raise ValueError(
                f"Access rule data for access type {access_type} can't be null"
            )
        validate_access_rules(this_type_rules)

        for each_rule in this_type_rules:
            compiled_rule = compile_access_rule(
                target_type=target_type,
                target_id=target_id,
                access_type=access_type,
                rule_data=each_rule,
            )
            if compiled_rule is not None:
                compiled_rules.append(compiled_rule)

    old_rule_set = target.access_rule_set
    new_rule_set = CompiledAccessRuleSet(node_id=target_id)
    new_rule_set.rules.extend(compiled_rules)
    session.add(new_rule_set)
    session.flush()

    target.access_rule_set = new_rule_set
    target.access_rule_set_id = new_rule_set.id
    session.flush()

    if old_rule_set is not None:
        session.delete(old_rule_set)


def apply_access_rules(
    target: Document | Folder,
    new_access_rules: dict[str, list[dict]],
    user: User,
    inherit_parent: bool = True,
) -> bool:
    """
    Attach access rules and verify the acting user still satisfies each rule.
    Only modifies the ORM object — does NOT commit.

    Returns False if any resulting rule would deny access to ``user``.
    """
    set_access_rules(target, new_access_rules, inherit_parent)
    session = object_session(target)
    if session is not None:
        session.flush()

    for access_type in new_access_rules:
        if not target.check_access_requirements(user, access_type):
            return False

    return True
