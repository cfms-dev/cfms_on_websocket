from tests.domains.access.test_compiled_access_rules_matching import (
    _make_rule_user,
    event,
    time,
)
from tests.domains.access.test_compiled_access_rules_synchronization import (
    _make_access_rule_user,
)


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
