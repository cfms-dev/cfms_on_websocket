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
