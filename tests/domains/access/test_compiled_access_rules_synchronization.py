from tests.domains.access.test_compiled_access_rules_matching import (
    Query,
    SAWarning,
    pytest,
    time,
    warnings,
)


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
