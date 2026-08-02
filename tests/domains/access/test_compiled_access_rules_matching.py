import sys
import time
from pathlib import Path

import pytest
import tomlkit
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
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
        session.add(models.Folder(id="/", name="/", inherit=False))
        session.commit()
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
