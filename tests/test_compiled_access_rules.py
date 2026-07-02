import sys
import time
from pathlib import Path

import pytest
import tomlkit
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

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
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    with SessionLocal() as session:
        yield models, session


def test_compiled_access_rules_match_legacy_json_evaluator(access_rule_session):
    models, session = access_rule_session
    from include.domains.access.authorization.access_rules import set_access_rules
    from include.domains.access.authorization.compiled_rules import (
        compiled_rules_allow,
        find_compiled_access_rule_mismatches,
        get_access_rules_json,
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
                "match": "all",
                "match_groups": [{"groups": {"match": "all", "require": ["sysop"]}}],
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
        get_access_rules_json(session, target_type="document", target_id=document.id)
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
            target_type="directory",
            target_id="missing-folder",
            access_type="read",
            match_mode="all",
        )
    )
    session.flush()

    assert find_compiled_access_rule_mismatches(session) == [
        ("directory", "missing-folder")
    ]


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
    session.flush()

    compiled_rule = session.query(models.CompiledAccessRule).one()
    compiled_group = compiled_rule.match_groups[0]
    assert [right.permission for right in compiled_group.rights] == ["list_users"]
    assert find_compiled_access_rule_mismatches(session) == []

    set_access_rules(document, {}, inherit_parent=False)
    session.flush()

    assert session.query(models.CompiledAccessRule).count() == 0
    assert find_compiled_access_rule_mismatches(session) == []


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

    session.delete(folder)
    session.flush()

    assert session.query(models.CompiledAccessRule).count() == 0
    assert find_compiled_access_rule_mismatches(session) == []


def test_compiled_access_rule_maintenance_detects_and_repairs_orphans(
    access_rule_session,
):
    models, session = access_rule_session
    from include.domains.access.authorization.access_rules import set_access_rules
    from include.domains.access.authorization.compiled_rules import (
        delete_compiled_access_rules_for_targets,
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

    delete_compiled_access_rules_for_targets(session, [("document", document.id)])
    session.add(
        models.CompiledAccessRule(
            target_type="document",
            target_id="missing-doc",
            access_type="read",
            match_mode="all",
        )
    )
    session.flush()

    assert find_compiled_access_rule_mismatches(session) == [
        ("document", "missing-doc"),
    ]
    assert find_compiled_access_rule_mismatches(session, include_orphans=False) == []

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
