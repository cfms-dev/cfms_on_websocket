import sys
import time
import warnings
from pathlib import Path

import pytest
import tomlkit
from sqlalchemy import create_engine, event
from sqlalchemy.exc import SAWarning
from sqlalchemy.orm import Query, sessionmaker

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_SRC_PATH = _PROJECT_ROOT / "src"


def _legacy_rule_data_matches_user(rule_data: dict, user) -> bool:
    def match_rights(sub_rights_group):
        if not sub_rights_group:
            return True
        sub_match_mode = sub_rights_group.get("match", "all")
        sub_rights_require = sub_rights_group.get("require", [])
        if not sub_rights_require:
            return True
        if sub_match_mode == "all":
            return set(sub_rights_require).issubset(user.all_permissions)
        if sub_match_mode == "any":
            return any(r in user.all_permissions for r in sub_rights_require)
        raise ValueError('the value of "match" must be "all" or "any"')

    def match_groups(sub_groups_group):
        if not sub_groups_group:
            return True
        sub_match_mode = sub_groups_group.get("match", "all")
        sub_groups_require = sub_groups_group.get("require", [])
        if not sub_groups_require:
            return True
        if sub_match_mode == "all":
            return set(sub_groups_require).issubset(user.all_groups)
        if sub_match_mode == "any":
            return any(g in user.all_groups for g in sub_groups_require)
        raise ValueError('the value of "match" must be "all" or "any"')

    def match_sub_group(sub_group):
        sub_match_mode = sub_group.get("match", "all")
        sub_rights_group = sub_group.get("rights", {})
        sub_groups_group = sub_group.get("groups", {})
        if not sub_rights_group.get("require", []) or not sub_groups_group.get(
            "require", []
        ):
            sub_match_mode = "all"
        if sub_match_mode == "any":
            return match_rights(sub_rights_group) or match_groups(sub_groups_group)
        if sub_match_mode == "all":
            return match_rights(sub_rights_group) and match_groups(sub_groups_group)
        raise ValueError('the value of "match" must be "all" or "any"')

    match_mode = rule_data.get("match", "all")
    for sub_group in rule_data.get("match_groups", []):
        if not sub_group:
            continue
        state = match_sub_group(sub_group)
        if match_mode == "any" and state:
            return True
        if match_mode == "all" and not state:
            return False

    return match_mode == "all"


def _legacy_access_rules_allow(access_rules, user, access_type: str) -> bool:
    relevant_access_types = {
        "read": ("read",),
        "write": ("read", "write"),
        "move": ("move",),
        "manage": ("read", "manage"),
    }[access_type]

    relevant_rules = [
        rule_data
        for relevant_access_type in relevant_access_types
        for rule_data in access_rules.get(relevant_access_type, [])
    ]
    if not relevant_rules:
        return True

    return all(
        _legacy_rule_data_matches_user(rule_data, user)
        for rule_data in relevant_rules
        if rule_data
    )


@pytest.fixture()
def access_rule_session(monkeypatch, tmp_path):
    if str(_SRC_PATH) not in sys.path:
        sys.path.insert(0, str(_SRC_PATH))

    config = tomlkit.parse((_SRC_PATH / "config.toml.sample").read_text("utf-8"))
    config["database"]["type"] = "sqlite"
    config["database"]["file"] = ":memory:"
    (tmp_path / "config.toml").write_text(tomlkit.dumps(config), encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    import include.database.models as models
    from include.database.session import Base

    engine = create_engine("sqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    with SessionLocal() as session:
        yield models, session


def _make_rule_user(models, session, *, permissions=(), groups=(), username="alice"):
    now = time.time()
    user = models.User(
        username=username,
        pass_hash="hash",
        passwd_last_modified=now,
        nickname=username,
        avatar_id=None,
        last_login=None,
        created_time=now,
        status=0,
        secret_key=f"{username}-secret",
        totp_secret=None,
        totp_enabled=False,
        totp_backup_codes=None,
        preference_dek_id=None,
    )
    for permission in permissions:
        user.rights.append(
            models.UserPermission(
                username=username,
                permission=permission,
                granted=True,
                start_time=0.0,
                end_time=None,
            )
        )
    for group_name in groups:
        if session.get(models.UserGroup, group_name) is None:
            session.add(
                models.UserGroup(
                    group_name=group_name,
                    group_display_name=group_name,
                )
            )
        user.groups.append(
            models.UserMembership(
                username=username,
                group_name=group_name,
                start_time=0.0,
                end_time=None,
            )
        )
    session.add(user)
    session.flush()
    return user


def test_compiled_access_rules_match_legacy_json_evaluator(access_rule_session):
    models, session = access_rule_session
    from include.domains.access.authorization.access_rules import set_access_rules
    from include.domains.access.authorization.compiled_rules import (
        compiled_rules_allow,
        find_compiled_access_rule_mismatches,
        get_access_rules_dict,
    )

    now = time.time()
    user = models.User(
        username="alice",
        pass_hash="hash",
        passwd_last_modified=now,
        nickname="Alice",
        avatar_id=None,
        last_login=None,
        created_time=now,
        status=0,
        secret_key="alice-secret",
        totp_secret=None,
        totp_enabled=False,
        totp_backup_codes=None,
        preference_dek_id=None,
    )
    user.rights.append(
        models.UserPermission(
            username="alice",
            permission="list_users",
            granted=True,
            start_time=0.0,
            end_time=None,
        )
    )
    group = models.UserGroup(group_name="staff", group_display_name="Staff")
    user.groups.append(
        models.UserMembership(
            username="alice",
            group_name="staff",
            start_time=0.0,
            end_time=None,
        )
    )
    document = models.Document(id="doc-1", title="Document", inherit=False)
    session.add_all([user, group, document])
    session.flush()

    rules = {
        "read": [
            {
                "match": "any",
                "match_groups": [
                    {
                        "match": "any",
                        "rights": {
                            "match": "any",
                            "require": ["debugging", "list_users"],
                        },
                        "groups": {
                            "match": "all",
                            "require": ["missing_group"],
                        },
                    }
                ],
            }
        ],
        "write": [
            {
                "match": "any",
                "match_groups": [
                    {
                        "match": "all",
                        "rights": {
                            "match": "any",
                            "require": [],
                        },
                        "groups": {"match": "all", "require": ["sysop"]},
                    }
                ],
            }
        ],
        "move": [
            {
                "match": "all",
                "match_groups": [{"groups": {"match": "all", "require": ["staff"]}}],
            }
        ],
        "manage": [
            {
                "match": "all",
                "match_groups": [
                    {"rights": {"match": "all", "require": ["list_users"]}}
                ],
            }
        ],
    }
    set_access_rules(
        document,
        rules,
        inherit_parent=False,
    )
    session.flush()

    assert find_compiled_access_rule_mismatches(session) == []
    assert (
        get_access_rules_dict(session, target_type="document", target_id=document.id)
        == rules
    )

    target_type = "document"
    expected = {
        "read": True,
        "write": False,
        "move": True,
        "manage": True,
    }
    for access_type, allowed in expected.items():
        assert _legacy_access_rules_allow(rules, user, access_type) is allowed
        assert (
            compiled_rules_allow(
                session,
                target_type=target_type,
                target_id=document.id,
                user=user,
                access_type=access_type,
            )
            is allowed
        )
        assert (
            document.check_access_requirements(
                user, access_type, _no_recursive_check=True
            )
            is allowed
        )


@pytest.mark.parametrize(
    (
        "document_id",
        "rules",
        "expected_rights_empty",
        "expected_groups_empty",
        "expected_serialized",
    ),
    [
        pytest.param(
            "doc-explicit-empty-rights",
            {
                "read": [
                    {
                        "match": "any",
                        "match_groups": [
                            {"rights": {"match": "any", "require": []}},
                        ],
                    }
                ]
            },
            False,
            True,
            {
                "read": [
                    {
                        "match": "any",
                        "match_groups": [
                            {"rights": {"match": "any", "require": []}},
                        ],
                    }
                ]
            },
            id="explicit-empty-rights",
        ),
        pytest.param(
            "doc-explicit-empty-groups",
            {
                "read": [
                    {
                        "match": "any",
                        "match_groups": [
                            {"groups": {"match": "any", "require": []}},
                        ],
                    }
                ]
            },
            True,
            False,
            {
                "read": [
                    {
                        "match": "any",
                        "match_groups": [
                            {"groups": {"match": "any", "require": []}},
                        ],
                    }
                ]
            },
            id="explicit-empty-groups",
        ),
        pytest.param(
            "doc-explicit-empty-rights-and-groups",
            {
                "read": [
                    {
                        "match": "any",
                        "match_groups": [
                            {
                                "match": "any",
                                "rights": {"match": "any", "require": []},
                                "groups": {"match": "any", "require": []},
                            },
                        ],
                    }
                ]
            },
            False,
            False,
            {
                "read": [
                    {
                        "match": "any",
                        "match_groups": [
                            {
                                "match": "all",
                                "rights": {"match": "any", "require": []},
                                "groups": {"match": "any", "require": []},
                            },
                        ],
                    }
                ]
            },
            id="explicit-empty-rights-and-groups",
        ),
    ],
)
def test_serialized_compiled_access_rule_preserves_explicit_empty_requirements(
    access_rule_session,
    document_id,
    rules,
    expected_rights_empty,
    expected_groups_empty,
    expected_serialized,
):
    models, session = access_rule_session
    from include.domains.access.authorization.access_rules import set_access_rules
    from include.domains.access.authorization.compiled_rules import (
        get_access_rules_dict,
    )

    document = models.Document(
        id=document_id,
        title="Explicit Empty Rights",
        inherit=False,
    )
    session.add(document)
    session.flush()

    set_access_rules(document, rules, inherit_parent=False)
    session.flush()

    compiled_group = session.query(models.CompiledAccessRuleGroup).one()
    assert compiled_group.rights_empty is expected_rights_empty
    assert compiled_group.groups_empty is expected_groups_empty
    assert (
        get_access_rules_dict(session, target_type="document", target_id=document.id)
        == expected_serialized
    )


@pytest.mark.parametrize(
    (
        "rules",
        "permissions",
        "groups",
        "access_type",
        "expected",
        "expected_serialized",
    ),
    [
        pytest.param({}, (), (), "read", True, {}, id="absence-of-rules-allows"),
        pytest.param(
            {
                "read": [{"match": "all", "match_groups": []}],
            },
            (),
            (),
            "read",
            True,
            {
                "read": [{"match": "all", "match_groups": []}],
            },
            id="empty-all-rule-allows",
        ),
        pytest.param(
            {
                "move": [{"match": "any", "match_groups": []}],
            },
            (),
            (),
            "move",
            False,
            {
                "move": [{"match": "any", "match_groups": []}],
            },
            id="empty-any-rule-denies",
        ),
        pytest.param(
            {
                "read": [{"match": "any", "match_groups": [{}]}],
            },
            (),
            (),
            "read",
            False,
            {
                "read": [{"match": "any", "match_groups": []}],
            },
            id="empty-subgroup-is-skipped",
        ),
        pytest.param(
            {
                "read": [
                    {
                        "match": "all",
                        "match_groups": [
                            {"rights": {"match": "all", "require": ["list_users"]}},
                        ],
                    }
                ],
            },
            ("list_users",),
            (),
            "read",
            True,
            {
                "read": [
                    {
                        "match": "all",
                        "match_groups": [
                            {"rights": {"match": "all", "require": ["list_users"]}},
                        ],
                    }
                ],
            },
            id="missing-groups-still-requires-rights",
        ),
        pytest.param(
            {
                "read": [
                    {
                        "match": "all",
                        "match_groups": [
                            {
                                "match": "any",
                                "groups": {"match": "all", "require": ["staff"]},
                            },
                        ],
                    }
                ],
            },
            (),
            (),
            "read",
            False,
            {
                "read": [
                    {
                        "match": "all",
                        "match_groups": [
                            {"groups": {"match": "all", "require": ["staff"]}},
                        ],
                    }
                ],
            },
            id="missing-rights-still-requires-groups",
        ),
        pytest.param(
            {
                "write": [
                    {
                        "match": "all",
                        "match_groups": [
                            {
                                "rights": {"match": "any", "require": []},
                                "groups": {"match": "all", "require": ["staff"]},
                            },
                        ],
                    }
                ],
            },
            (),
            (),
            "write",
            False,
            {
                "write": [
                    {
                        "match": "all",
                        "match_groups": [
                            {
                                "match": "all",
                                "rights": {"match": "any", "require": []},
                                "groups": {"match": "all", "require": ["staff"]},
                            },
                        ],
                    }
                ],
            },
            id="explicit-empty-rights-does-not-bypass-groups",
        ),
        pytest.param(
            {
                "read": [
                    {
                        "match": "all",
                        "match_groups": [
                            {
                                "rights": {"match": "all", "require": ["debugging"]},
                                "groups": {"match": "any", "require": []},
                            },
                        ],
                    }
                ],
            },
            (),
            (),
            "read",
            False,
            {
                "read": [
                    {
                        "match": "all",
                        "match_groups": [
                            {
                                "match": "all",
                                "rights": {"match": "all", "require": ["debugging"]},
                                "groups": {"match": "any", "require": []},
                            },
                        ],
                    }
                ],
            },
            id="explicit-empty-groups-does-not-bypass-rights",
        ),
        pytest.param(
            {
                "read": [
                    {
                        "match": "all",
                        "match_groups": [
                            {
                                "match": "any",
                                "rights": {"match": "any", "require": []},
                                "groups": {"match": "any", "require": []},
                            },
                        ],
                    }
                ],
            },
            (),
            (),
            "read",
            True,
            {
                "read": [
                    {
                        "match": "all",
                        "match_groups": [
                            {
                                "match": "all",
                                "rights": {"match": "any", "require": []},
                                "groups": {"match": "any", "require": []},
                            },
                        ],
                    }
                ],
            },
            id="both-explicit-empty-requirements-allow",
        ),
        pytest.param(
            {
                "read": [
                    {
                        "match": "all",
                        "match_groups": [
                            {
                                "match": "any",
                                "rights": {"match": "all", "require": ["list_users"]},
                                "groups": {"match": "all", "require": ["sysop"]},
                            },
                        ],
                    }
                ],
            },
            ("list_users",),
            (),
            "read",
            True,
            {
                "read": [
                    {
                        "match": "all",
                        "match_groups": [
                            {
                                "match": "any",
                                "rights": {"match": "all", "require": ["list_users"]},
                                "groups": {"match": "all", "require": ["sysop"]},
                            },
                        ],
                    }
                ],
            },
            id="subgroup-any-accepts-one-side",
        ),
        pytest.param(
            {
                "read": [
                    {
                        "match": "all",
                        "match_groups": [
                            {
                                "match": "all",
                                "rights": {"match": "all", "require": ["list_users"]},
                                "groups": {"match": "all", "require": ["sysop"]},
                            },
                        ],
                    }
                ],
            },
            ("list_users",),
            (),
            "read",
            False,
            {
                "read": [
                    {
                        "match": "all",
                        "match_groups": [
                            {
                                "match": "all",
                                "rights": {"match": "all", "require": ["list_users"]},
                                "groups": {"match": "all", "require": ["sysop"]},
                            },
                        ],
                    }
                ],
            },
            id="subgroup-all-requires-both-sides",
        ),
        pytest.param(
            {
                "read": [
                    {
                        "match": "any",
                        "match_groups": [
                            {"rights": {"match": "all", "require": ["debugging"]}},
                            {"groups": {"match": "all", "require": ["staff"]}},
                        ],
                    }
                ],
            },
            (),
            ("staff",),
            "read",
            True,
            {
                "read": [
                    {
                        "match": "any",
                        "match_groups": [
                            {"rights": {"match": "all", "require": ["debugging"]}},
                            {"groups": {"match": "all", "require": ["staff"]}},
                        ],
                    }
                ],
            },
            id="rule-any-accepts-one-matching-subgroup",
        ),
        pytest.param(
            {
                "read": [
                    {
                        "match": "all",
                        "match_groups": [
                            {"rights": {"match": "all", "require": ["list_users"]}},
                        ],
                    },
                    {
                        "match": "all",
                        "match_groups": [
                            {"groups": {"match": "all", "require": ["sysop"]}},
                        ],
                    },
                ],
            },
            ("list_users",),
            (),
            "read",
            False,
            {
                "read": [
                    {
                        "match": "all",
                        "match_groups": [
                            {"rights": {"match": "all", "require": ["list_users"]}},
                        ],
                    },
                    {
                        "match": "all",
                        "match_groups": [
                            {"groups": {"match": "all", "require": ["sysop"]}},
                        ],
                    },
                ],
            },
            id="multiple-rules-are-anded",
        ),
        pytest.param(
            {
                "read": [
                    {
                        "match": "all",
                        "match_groups": [
                            {"rights": {"match": "all", "require": ["debugging"]}},
                        ],
                    }
                ],
                "manage": [
                    {
                        "match": "all",
                        "match_groups": [
                            {"groups": {"match": "all", "require": ["staff"]}},
                        ],
                    }
                ],
            },
            (),
            ("staff",),
            "manage",
            False,
            {
                "read": [
                    {
                        "match": "all",
                        "match_groups": [
                            {"rights": {"match": "all", "require": ["debugging"]}},
                        ],
                    }
                ],
                "manage": [
                    {
                        "match": "all",
                        "match_groups": [
                            {"groups": {"match": "all", "require": ["staff"]}},
                        ],
                    }
                ],
            },
            id="manage-also-requires-read-rules",
        ),
    ],
)
def test_compiled_access_rule_edge_cases_match_legacy_json_evaluator(
    access_rule_session,
    rules,
    permissions,
    groups,
    access_type,
    expected,
    expected_serialized,
):
    models, session = access_rule_session
    from include.domains.access.authorization.access_rules import set_access_rules
    from include.domains.access.authorization.compiled_rules import (
        compiled_rules_allow,
        compiled_rules_allow_from_map,
        fetch_compiled_access_rules_for_targets,
        find_compiled_access_rule_mismatches,
        get_access_rules_dict,
    )

    user = _make_rule_user(
        models,
        session,
        permissions=permissions,
        groups=groups,
    )
    document = models.Document(id="doc-edge-case", title="Edge Case", inherit=False)
    session.add(document)
    session.flush()

    set_access_rules(document, rules, inherit_parent=False)
    session.flush()

    rules_by_target = fetch_compiled_access_rules_for_targets(
        session,
        [("document", document.id)],
    )

    assert find_compiled_access_rule_mismatches(session) == []
    assert (
        get_access_rules_dict(session, target_type="document", target_id=document.id)
        == expected_serialized
    )
    assert _legacy_access_rules_allow(rules, user, access_type) is expected
    assert (
        compiled_rules_allow(
            session,
            target_type="document",
            target_id=document.id,
            user=user,
            access_type=access_type,
        )
        is expected
    )
    assert (
        compiled_rules_allow_from_map(
            rules_by_target,
            target_type="document",
            target_id=document.id,
            user=user,
            access_type=access_type,
        )
        is expected
    )
    assert (
        document.check_access_requirements(user, access_type, _no_recursive_check=True)
        is expected
    )


def test_compiled_access_rule_mismatch_detector_reports_invalid_rows(
    access_rule_session,
):
    models, session = access_rule_session
    from include.domains.access.authorization.access_rules import set_access_rules
    from include.domains.access.authorization.compiled_rules import (
        find_compiled_access_rule_mismatches,
    )

    folder = models.Folder(id="folder-1", name="Folder", inherit=False)
    session.add(folder)
    session.flush()
    set_access_rules(
        folder,
        {
            "read": [
                {
                    "match": "all",
                    "match_groups": [
                        {"groups": {"match": "all", "require": ["sysop"]}}
                    ],
                }
            ]
        },
        inherit_parent=False,
    )
    session.flush()

    assert find_compiled_access_rule_mismatches(session) == []

    session.add(
        models.CompiledAccessRule(
            rule_set=models.CompiledAccessRuleSet(node_id=folder.id),
            access_type="invalid",
            match_mode="all",
        )
    )
    session.flush()

    assert find_compiled_access_rule_mismatches(session) == [("directory", folder.id)]


def test_compiled_access_rule_repair_removes_invalid_shape(access_rule_session):
    models, session = access_rule_session
    from include.domains.access.authorization.access_rules import set_access_rules
    from include.domains.access.authorization.compiled_rules import (
        find_compiled_access_rule_mismatches,
        repair_compiled_access_rules,
    )

    document = models.Document(id="doc-invalid-shape", title="Document", inherit=False)
    session.add(document)
    session.flush()
    set_access_rules(
        document,
        {
            "read": [
                {
                    "match": "all",
                    "match_groups": [
                        {"groups": {"match": "all", "require": ["staff"]}}
                    ],
                }
            ]
        },
        inherit_parent=False,
    )
    session.flush()

    compiled_rule = session.query(models.CompiledAccessRule).one()
    compiled_rule.match_groups[0].groups_match_mode = "invalid"
    session.flush()

    assert find_compiled_access_rule_mismatches(session) == [
        ("document", document.id),
    ]
    assert repair_compiled_access_rules(session) == []
    assert session.query(models.CompiledAccessRule).count() == 0
    assert session.query(models.CompiledAccessRuleSet).count() == 0
    assert document.access_rule_set_id is None


def test_set_access_rules_keeps_compiled_rows_in_sync(access_rule_session):
    models, session = access_rule_session
    from include.domains.access.authorization.access_rules import set_access_rules
    from include.domains.access.authorization.compiled_rules import (
        find_compiled_access_rule_mismatches,
    )

    document = models.Document(id="doc-sync", title="Document", inherit=False)
    session.add(document)
    session.flush()

    set_access_rules(
        document,
        {
            "read": [
                {
                    "match": "all",
                    "match_groups": [
                        {"groups": {"match": "all", "require": ["staff"]}}
                    ],
                }
            ]
        },
        inherit_parent=False,
    )
    session.flush()

    assert session.query(models.CompiledAccessRule).count() == 1
    assert session.query(models.CompiledAccessRuleSet).count() == 1
    assert document.access_rule_set is not None
    assert find_compiled_access_rule_mismatches(session) == []

    set_access_rules(
        document,
        {
            "read": [
                {
                    "match": "all",
                    "match_groups": [
                        {"rights": {"match": "all", "require": ["list_users"]}}
                    ],
                }
            ]
        },
        inherit_parent=False,
    )
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "error",
            message="Identity map already had an identity.*",
            category=SAWarning,
        )
        session.flush()

    compiled_rule = session.query(models.CompiledAccessRule).one()
    compiled_group = compiled_rule.match_groups[0]
    assert session.query(models.CompiledAccessRuleSet).count() == 1
    assert document.access_rule_set_id == compiled_rule.rule_set_id
    assert isinstance(compiled_group.id, str)
    assert len(compiled_group.id) == 32
    assert [right.permission for right in compiled_group.rights] == ["list_users"]
    assert [right.group_id for right in compiled_group.rights] == [compiled_group.id]
    assert session.query(models.CompiledAccessRuleGroup).count() == 1
    assert session.query(models.CompiledAccessRuleMembership).count() == 0
    assert session.query(models.CompiledAccessRuleRight).count() == 1
    assert find_compiled_access_rule_mismatches(session) == []

    set_access_rules(document, {}, inherit_parent=False)
    session.flush()

    assert session.query(models.CompiledAccessRule).count() == 0
    assert session.query(models.CompiledAccessRuleSet).count() == 0
    assert document.access_rule_set is None
    assert document.access_rule_set_id is None
    assert session.query(models.CompiledAccessRuleGroup).count() == 0
    assert session.query(models.CompiledAccessRuleMembership).count() == 0
    assert session.query(models.CompiledAccessRuleRight).count() == 0
    assert find_compiled_access_rule_mismatches(session) == []


def test_set_access_rules_accepts_pending_folder(access_rule_session):
    models, session = access_rule_session
    from include.domains.access.authorization.access_rules import set_access_rules
    from include.domains.access.authorization.compiled_rules import (
        find_compiled_access_rule_mismatches,
    )

    folder = models.Folder(name="Pending Folder", inherit=True)
    session.add(folder)

    set_access_rules(
        folder,
        {
            "read": [
                {
                    "match": "all",
                    "match_groups": [
                        {"groups": {"match": "all", "require": ["staff"]}}
                    ],
                }
            ]
        },
        inherit_parent=False,
    )
    session.flush()

    assert folder.id is not None
    assert folder.inherit is False
    assert session.query(models.CompiledAccessRule).count() == 1
    assert session.query(models.CompiledAccessRuleSet).one().node_id == folder.id
    assert find_compiled_access_rule_mismatches(session) == []


def test_set_access_rules_locks_target_node(access_rule_session, monkeypatch):
    models, session = access_rule_session
    from include.domains.access.authorization.access_rules import set_access_rules

    lock_calls = []
    original_with_for_update = Query.with_for_update

    def tracking_with_for_update(self, *args, **kwargs):
        lock_calls.append(self)
        return original_with_for_update(self, *args, **kwargs)

    monkeypatch.setattr(Query, "with_for_update", tracking_with_for_update)

    document = models.Document(id="doc-lock", title="Document", inherit=False)
    session.add(document)
    session.flush()

    set_access_rules(document, {}, inherit_parent=False)

    assert lock_calls
    assert document.access_rule_set is None


def test_set_access_rules_discards_new_rows_when_guarded_update_fails(
    access_rule_session,
    monkeypatch,
):
    models, session = access_rule_session
    from include.domains.access.authorization.access_rules import set_access_rules

    document = models.Document(id="doc-stale-update", title="Document", inherit=False)
    session.add(document)
    session.flush()

    original_update = Query.update

    def stale_update(self, values, *args, **kwargs):
        if any(getattr(key, "key", None) == "access_rule_set_id" for key in values):
            return 0
        return original_update(self, values, *args, **kwargs)

    monkeypatch.setattr(Query, "update", stale_update)

    with pytest.raises(RuntimeError, match="changed concurrently"):
        set_access_rules(
            document,
            {
                "read": [
                    {
                        "match": "all",
                        "match_groups": [
                            {"groups": {"match": "all", "require": ["staff"]}}
                        ],
                    }
                ]
            },
            inherit_parent=False,
        )

    session.flush()
    assert session.query(models.CompiledAccessRuleSet).count() == 0
    assert session.query(models.CompiledAccessRule).count() == 0
    assert document.access_rule_set_id is None


def test_orm_delete_removes_compiled_access_rules(access_rule_session):
    models, session = access_rule_session
    from include.domains.access.authorization.access_rules import set_access_rules
    from include.domains.access.authorization.compiled_rules import (
        find_compiled_access_rule_mismatches,
    )

    folder = models.Folder(id="folder-delete", name="Folder", inherit=False)
    session.add(folder)
    session.flush()
    set_access_rules(
        folder,
        {
            "read": [
                {
                    "match": "all",
                    "match_groups": [
                        {"groups": {"match": "all", "require": ["staff"]}}
                    ],
                }
            ]
        },
        inherit_parent=False,
    )
    session.flush()

    assert session.query(models.CompiledAccessRule).count() == 1
    assert session.query(models.CompiledAccessRuleSet).count() == 1

    session.delete(folder)
    session.flush()

    assert session.query(models.CompiledAccessRule).count() == 0
    assert session.query(models.CompiledAccessRuleSet).count() == 0
    assert find_compiled_access_rule_mismatches(session) == []


def test_compiled_access_rule_maintenance_detects_and_repairs_invalid_rows(
    access_rule_session,
):
    models, session = access_rule_session
    from include.domains.access.authorization.access_rules import set_access_rules
    from include.domains.access.authorization.compiled_rules import (
        find_compiled_access_rule_mismatches,
        repair_compiled_access_rules,
    )

    document = models.Document(id="doc-maintenance", title="Document", inherit=False)
    folder = models.Folder(id="folder-maintenance", name="Folder", inherit=False)
    session.add_all([document, folder])
    session.flush()
    set_access_rules(
        document,
        {
            "read": [
                {
                    "match": "all",
                    "match_groups": [
                        {"groups": {"match": "all", "require": ["staff"]}}
                    ],
                }
            ]
        },
        inherit_parent=False,
    )
    set_access_rules(
        folder,
        {
            "read": [
                {
                    "match": "all",
                    "match_groups": [
                        {"groups": {"match": "all", "require": ["staff"]}}
                    ],
                }
            ]
        },
        inherit_parent=False,
    )
    session.flush()

    session.add(
        models.CompiledAccessRule(
            rule_set=models.CompiledAccessRuleSet(node_id=document.id),
            access_type="invalid",
            match_mode="all",
        )
    )
    session.flush()

    assert find_compiled_access_rule_mismatches(session) == [
        ("document", document.id),
    ]
    assert find_compiled_access_rule_mismatches(session, include_orphans=False) == [
        ("document", document.id),
    ]

    assert repair_compiled_access_rules(session) == []
    assert find_compiled_access_rule_mismatches(session) == []


def test_compiled_access_rule_repair_does_not_rebuild_missing_rows(
    access_rule_session,
):
    models, session = access_rule_session
    from include.domains.access.authorization.access_rules import set_access_rules
    from include.domains.access.authorization.compiled_rules import (
        delete_compiled_access_rules_for_targets,
        find_compiled_access_rule_mismatches,
        repair_compiled_access_rules,
    )

    document = models.Document(id="doc-no-rebuild", title="Document", inherit=False)
    session.add(document)
    session.flush()
    set_access_rules(
        document,
        {
            "read": [
                {
                    "match": "all",
                    "match_groups": [
                        {"groups": {"match": "all", "require": ["staff"]}}
                    ],
                }
            ]
        },
        inherit_parent=False,
    )
    session.flush()

    delete_compiled_access_rules_for_targets(session, [("document", document.id)])
    session.flush()

    assert find_compiled_access_rule_mismatches(session) == []
    assert repair_compiled_access_rules(session) == []
    assert session.query(models.CompiledAccessRule).count() == 0


def test_compiled_access_rule_repair_removes_empty_and_inactive_rule_sets(
    access_rule_session,
):
    models, session = access_rule_session
    from include.domains.access.authorization.compiled_rules import (
        find_compiled_access_rule_mismatches,
        repair_compiled_access_rules,
    )

    empty_active_node = models.Document(
        id="doc-empty-active",
        title="Empty Active",
        inherit=False,
    )
    inactive_node = models.Document(
        id="doc-inactive-ruleset",
        title="Inactive Rule Set",
        inherit=False,
    )
    mismatched_node = models.Document(
        id="doc-mismatched-active",
        title="Mismatched Active",
        inherit=False,
    )
    owner_node = models.Document(id="doc-owner", title="Owner", inherit=False)
    session.add_all([empty_active_node, inactive_node, mismatched_node, owner_node])
    session.flush()

    empty_active_rule_set = models.CompiledAccessRuleSet(node_id=empty_active_node.id)
    inactive_rule_set = models.CompiledAccessRuleSet(node_id=inactive_node.id)
    inactive_rule_set.rules.append(
        models.CompiledAccessRule(access_type="read", match_mode="all")
    )
    mismatched_rule_set = models.CompiledAccessRuleSet(node_id=owner_node.id)
    mismatched_rule_set.rules.append(
        models.CompiledAccessRule(access_type="read", match_mode="all")
    )
    session.add_all([empty_active_rule_set, inactive_rule_set, mismatched_rule_set])
    session.flush()

    empty_active_node.access_rule_set_id = empty_active_rule_set.id
    mismatched_node.access_rule_set_id = mismatched_rule_set.id
    session.flush()

    assert find_compiled_access_rule_mismatches(session) == [
        ("document", empty_active_node.id),
        ("document", inactive_node.id),
        ("document", mismatched_node.id),
    ]

    assert repair_compiled_access_rules(session) == []
    assert session.query(models.CompiledAccessRuleSet).count() == 0
    assert session.query(models.CompiledAccessRule).count() == 0
    assert empty_active_node.access_rule_set_id is None
    assert mismatched_node.access_rule_set_id is None


def test_delete_compiled_access_rules_validates_target_type(access_rule_session):
    models, session = access_rule_session
    from include.domains.access.authorization.access_rules import set_access_rules
    from include.domains.access.authorization.compiled_rules import (
        delete_compiled_access_rules_for_targets,
    )

    folder = models.Folder(id="folder-type-check", name="Folder", inherit=False)
    document = models.Document(id="doc-type-check", title="Document", inherit=False)
    session.add_all([folder, document])
    session.flush()

    set_access_rules(
        folder,
        {
            "read": [
                {
                    "match": "all",
                    "match_groups": [
                        {"groups": {"match": "all", "require": ["staff"]}}
                    ],
                }
            ]
        },
        inherit_parent=False,
    )
    session.flush()

    with pytest.raises(ValueError):
        delete_compiled_access_rules_for_targets(session, [("document", folder.id)])

    assert session.get(models.Folder, folder.id).access_rule_set_id is not None
    assert session.query(models.CompiledAccessRuleSet).count() == 1

    delete_compiled_access_rules_for_targets(session, [("directory", folder.id)])
    session.flush()

    assert session.get(models.Folder, folder.id).access_rule_set_id is None
    assert session.query(models.CompiledAccessRuleSet).count() == 0
    assert session.query(models.CompiledAccessRule).count() == 0


def _make_access_rule_user(models, session, username="alice"):
    now = time.time()
    user = models.User(
        username=username,
        pass_hash="hash",
        passwd_last_modified=now,
        nickname=username,
        avatar_id=None,
        last_login=None,
        created_time=now,
        status=0,
        secret_key=f"{username}-secret",
        totp_secret=None,
        totp_enabled=False,
        totp_backup_codes=None,
        preference_dek_id=None,
    )
    for permission in (
        "delete_document",
        "delete_directory",
        "list_users",
    ):
        user.rights.append(
            models.UserPermission(
                username=username,
                permission=permission,
                granted=True,
                start_time=0.0,
                end_time=None,
            )
        )
    session.add(user)
    session.flush()
    return user


def test_fetch_subtree_deletion_prefetches_compiled_rules_once(
    access_rule_session,
):
    models, session = access_rule_session
    from include.domains.documents.queries.deletion_tree import (
        fetch_subtree_for_deletion,
    )

    user = _make_access_rule_user(models, session)
    root = models.Folder(id="root-folder", name="Root", inherit=False)
    session.add(root)
    session.flush()

    for index in range(250):
        session.add(
            models.Document(
                id=f"doc-{index}",
                title=f"Document {index}",
                folder_id=root.id,
                inherit=True,
            )
        )
    session.commit()

    statements: list[str] = []

    def before_cursor_execute(_conn, _cursor, statement, *_args):
        if "FROM compiled_access_rules" in " ".join(statement.split()):
            statements.append(statement)

    engine = session.get_bind()
    event.listen(engine, "before_cursor_execute", before_cursor_execute)
    try:
        _, deletable_doc_ids, failed_items, protected_folder_ids, _ = (
            fetch_subtree_for_deletion(session, root.id, user)
        )
    finally:
        event.remove(engine, "before_cursor_execute", before_cursor_execute)

    assert len(deletable_doc_ids) == 250
    assert failed_items == []
    assert protected_folder_ids == set()
    assert len(statements) <= 2


def test_batched_compiled_rules_match_direct_access_checks(access_rule_session):
    models, session = access_rule_session
    from include.domains.access.authorization.access_rules import set_access_rules
    from include.domains.access.authorization.compiled_rules import (
        fetch_compiled_access_rules_for_targets,
    )
    from include.domains.access.authorization.evaluation import check_access_for_object

    user = _make_access_rule_user(models, session)
    parent = models.Folder(id="parent", name="Parent", inherit=False)
    inherited_doc = models.Document(
        id="inherited-doc",
        title="Inherited",
        folder=parent,
        inherit=True,
    )
    self_rule_doc = models.Document(
        id="self-rule-doc",
        title="Self Rule",
        folder=parent,
        inherit=False,
    )
    default_doc = models.Document(
        id="default-doc",
        title="Default",
        folder=parent,
        inherit=False,
    )
    session.add_all([parent, inherited_doc, self_rule_doc, default_doc])
    session.flush()

    set_access_rules(
        parent,
        {
            "read": [
                {
                    "match": "all",
                    "match_groups": [
                        {"rights": {"match": "all", "require": ["list_users"]}}
                    ],
                }
            ]
        },
        inherit_parent=False,
    )
    set_access_rules(
        self_rule_doc,
        {
            "write": [
                {
                    "match": "all",
                    "match_groups": [
                        {"rights": {"match": "all", "require": ["debugging"]}}
                    ],
                }
            ]
        },
        inherit_parent=False,
    )
    session.flush()

    rules_by_target = fetch_compiled_access_rules_for_targets(
        session,
        [
            ("directory", parent.id),
            ("document", inherited_doc.id),
            ("document", self_rule_doc.id),
            ("document", default_doc.id),
        ],
    )
    folders = [parent]
    folder_map = {parent.id: parent}

    for obj, access_type in (
        (default_doc, "write"),
        (inherited_doc, "write"),
        (self_rule_doc, "write"),
    ):
        direct = check_access_for_object(
            obj,
            user,
            access_type,
            all_folders=folders,
            oae_by_target={},
        )
        batched = check_access_for_object(
            obj,
            user,
            access_type,
            all_folders=folders,
            oae_by_target={},
            compiled_rules_by_target=rules_by_target,
            folder_map=folder_map,
        )
        assert batched is direct


def test_folder_access_context_hides_blocked_parent_but_honors_direct_grant(
    access_rule_session,
):
    models, session = access_rule_session
    from include.domains.access.authorization.evaluation import (
        load_folder_access_evaluation_context,
    )

    user = _make_rule_user(models, session)
    parent = models.Folder(id="context-parent", name="Context Parent", inherit=False)
    child = models.Folder(
        id="context-child",
        name="Context Child",
        parent=parent,
        inherit=True,
    )
    session.add_all([parent, child])
    session.flush()

    block = models.UserBlockEntry(
        username=user.username,
        timestamp=time.time(),
        not_before=0.0,
        not_after=-1,
        target_type="directory",
        target_id=parent.id,
    )
    block.sub_entries.append(models.UserBlockSubEntry(block_type="read"))
    session.add(block)
    session.flush()

    denied_context = load_folder_access_evaluation_context(
        session, [child], user, "read"
    )
    assert denied_context.allows(child) is False
    assert denied_context.allows(parent) is False
    assert child.check_access_requirements(user, "read") is False

    expired_entry = models.ObjectAccessEntry(
        entity_type="user",
        entity_identifier=user.username,
        target_type="directory",
        target_identifier=child.id,
        access_type="read",
        start_time=0.0,
        end_time=time.time() - 1,
    )
    session.add(expired_entry)
    session.flush()
    expired_context = load_folder_access_evaluation_context(
        session, [child], user, "read"
    )
    assert expired_context.allows(child) is False
    assert expired_context.oae_by_target.get(child.id, []) == []

    active_entry = models.ObjectAccessEntry(
        entity_type="user",
        entity_identifier=user.username,
        target_type="directory",
        target_identifier=child.id,
        access_type="read",
        start_time=0.0,
        end_time=None,
    )
    session.add(active_entry)
    session.flush()

    granted_context = load_folder_access_evaluation_context(
        session, [child], user, "read"
    )
    assert granted_context.allows(child) is True
    assert granted_context.allows(parent) is False
    assert child.check_access_requirements(user, "read") is True

    block.target_type = "all"
    block.target_id = None
    session.flush()
    globally_blocked_context = load_folder_access_evaluation_context(
        session, [child], user, "read"
    )
    assert globally_blocked_context.allows(child) is False
    assert child.check_access_requirements(user, "read") is False

    block.target_type = "directory"
    block.target_id = parent.id
    active_entry.end_time = time.time() - 1
    group = models.UserGroup(group_name="context-group", group_display_name="Context")
    user.groups.append(
        models.UserMembership(
            username=user.username,
            group_name=group.group_name,
            start_time=0.0,
            end_time=None,
        )
    )
    session.add(group)
    session.add(
        models.ObjectAccessEntry(
            entity_type="group",
            entity_identifier=group.group_name,
            target_type="directory",
            target_identifier=child.id,
            access_type="read",
            start_time=0.0,
            end_time=None,
        )
    )
    session.flush()
    group_context = load_folder_access_evaluation_context(
        session, [child], user, "read"
    )
    assert group_context.allows(child) is True
    assert child.check_access_requirements(user, "read") is True

    child.inherit = False
    session.query(models.ObjectAccessEntry).filter_by(entity_type="group").delete()
    session.flush()
    non_inheriting_context = load_folder_access_evaluation_context(
        session, [child], user, "read"
    )
    assert non_inheriting_context.allows(child) is True
    assert non_inheriting_context.allows(parent) is False
    assert child.check_access_requirements(user, "read") is True


def test_folder_access_context_reuses_queries_across_depth(access_rule_session):
    models, session = access_rule_session
    from include.domains.access.authorization.evaluation import (
        load_folder_access_evaluation_context,
    )

    user = _make_rule_user(models, session)
    root = models.Folder(id="query-root", name="Query Root", inherit=False)
    shallow = models.Folder(
        id="query-shallow", name="Query Shallow", parent=root, inherit=True
    )
    middle = models.Folder(
        id="query-middle", name="Query Middle", parent=shallow, inherit=True
    )
    deep = models.Folder(
        id="query-deep", name="Query Deep", parent=middle, inherit=True
    )
    session.add_all([root, shallow, middle, deep])
    session.commit()
    _ = (user.all_groups, user.all_permissions)

    def load_with_statement_count(folder):
        statements: list[str] = []

        def collect_statement(_conn, _cursor, statement, *_args):
            statements.append(statement)

        event.listen(session.bind, "before_cursor_execute", collect_statement)
        try:
            context = load_folder_access_evaluation_context(
                session, [folder], user, "read"
            )
        finally:
            event.remove(session.bind, "before_cursor_execute", collect_statement)
        return context, len(statements)

    shallow_context, shallow_statement_count = load_with_statement_count(shallow)
    deep_context, deep_statement_count = load_with_statement_count(deep)
    assert deep_statement_count == shallow_statement_count

    evaluation_statements: list[str] = []

    def collect_evaluation_statement(_conn, _cursor, statement, *_args):
        evaluation_statements.append(statement)

    event.listen(session.bind, "before_cursor_execute", collect_evaluation_statement)
    try:
        assert deep_context.allows(deep) is True
        assert deep_context.allows(middle) is True
    finally:
        event.remove(
            session.bind, "before_cursor_execute", collect_evaluation_statement
        )
    assert evaluation_statements == []

    def direct_statement_count(folder_id: str) -> int:
        session.expire_all()
        direct_user = session.get(models.User, "alice")
        folder = session.get(models.Folder, folder_id)
        assert direct_user is not None
        assert folder is not None
        _ = (direct_user.all_groups, direct_user.all_permissions)
        statements: list[str] = []

        def collect_direct_statement(_conn, _cursor, statement, *_args):
            statements.append(statement)

        event.listen(session.bind, "before_cursor_execute", collect_direct_statement)
        try:
            assert folder.check_access_requirements(direct_user, "read") is True
            assert folder.parent is not None
            assert folder.parent.check_access_requirements(direct_user, "read") is True
        finally:
            event.remove(
                session.bind, "before_cursor_execute", collect_direct_statement
            )
        return len(statements)

    assert shallow_statement_count <= direct_statement_count("query-shallow")
    assert deep_statement_count <= direct_statement_count("query-deep")
