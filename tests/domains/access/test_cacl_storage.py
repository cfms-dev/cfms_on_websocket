"""Component tests for CACL storage, compilation, decompilation, and time-window evaluation."""

import datetime

import pytest
from cacl_compiler import AtomicOp, ObjectType
from sqlalchemy import event, select
from sqlalchemy.orm import sessionmaker

from include.config.constants import DACL_MAX_RULES_PER_NODE
from include.database import models
from include.database.models.access import datetime_to_epoch_us, epoch_us_to_datetime
from include.database.session import Base
from include.domains.access.authorization.evaluation import (
    authorize_dacl_read,
    authorize_dacl_save,
    authorize_directory_access_with_parent,
    authorize_node_operation,
    authorize_soft_delete_descendants,
    check_directory_soft_delete_root,
    would_self_lockout_on_create,
)
from include.domains.access.authorization.storage import (
    DEFAULT_ROOT_DACL_SOURCE,
    compile_policy_source,
    load_node_policies,
    persist_node_policy,
    render_policy_text,
)
from include.domains.access.permissions import Permissions
from include.domains.documents.queries.deletion_tree import (
    fetch_subtree_metadata_for_soft_delete,
)

pytestmark = pytest.mark.component


@pytest.fixture
def cacl_session(sqlite_engine_factory):
    engine = sqlite_engine_factory(":memory:")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    with SessionLocal() as session:
        root = models.Folder(id="/", name="/", inherit=False)
        session.add(root)
        session.flush()
        compiled = compile_policy_source(session, DEFAULT_ROOT_DACL_SOURCE)
        assert compiled.policy is not None
        persist_node_policy(session, root, compiled.policy)
        session.commit()
        yield session


def test_compile_persist_load_and_render_round_trip(cacl_session):
    alice = models.User(
        username="alice",
        nickname="Alice",
        created_time=1.0,
        status=0,
        secret_key="s" * 64,
    )
    eng = models.UserGroup(group_name="engineering", group_display_name="Engineering")
    cacl_session.add_all([alice, eng])
    cacl_session.flush()

    folder = models.Folder(id="f1", name="F1", parent_id="/", inherit=True)
    cacl_session.add(folder)
    cacl_session.flush()

    source = (
        "inherit off;\n"
        f'allow [READ_CONTENT, READ_METADATA] on docs when (user("{alice.id}") or (group("engineering") and not group("interns"))) '
        'from "2026-01-01T00:00:00Z" until "2027-01-01T00:00:00Z";\n'
        f'deny [WRITE_CONTENT] on self to user("{alice.id}");\n'
    )
    compiled = compile_policy_source(cacl_session, source)
    assert not compiled.errors
    assert any(d.code == "W304" for d in compiled.warnings)
    assert compiled.policy is not None

    persist_node_policy(cacl_session, folder, compiled.policy)
    cacl_session.commit()

    assert folder.inherit is False
    assert len(cacl_session.scalars(select(models.NodeDaclRule)).all()) >= 2

    loaded = load_node_policies(cacl_session, [folder.id])
    policy = loaded[folder.id]
    assert policy.fingerprint() == compiled.policy.fingerprint()

    plain = render_policy_text(policy, session=cacl_session, annotate_users=False)
    annotated = render_policy_text(policy, session=cacl_session, annotate_users=True)
    assert "inherit off;" in plain
    assert "alice" not in plain
    assert "alice" in annotated


def test_compile_rejects_malformed_uuid_but_warns_on_missing_user(cacl_session):
    malformed = compile_policy_source(
        cacl_session, 'allow [READ_CONTENT] to user("not-a-uuid");'
    )
    assert malformed.errors
    assert malformed.policy is None

    missing = compile_policy_source(
        cacl_session,
        'allow [READ_CONTENT] to user("00000000-0000-4000-8000-000000000001");',
    )
    assert not missing.errors
    assert any(w.code == "W301" for w in missing.warnings)
    assert missing.policy is not None


def test_half_open_time_window_and_next_transition_at(cacl_session):
    alice = models.User(
        username="alice",
        nickname="Alice",
        created_time=1.0,
        status=0,
        secret_key="s" * 64,
    )
    cacl_session.add(alice)
    cacl_session.flush()

    doc = models.Document(id="d1", title="D1", folder_id="/", inherit=False)
    cacl_session.add(doc)
    cacl_session.flush()

    compiled = compile_policy_source(
        cacl_session,
        (
            "inherit off;\n"
            f'allow [READ_CONTENT] to user("{alice.id}") '
            'from "2026-06-01T00:00:00Z" until "2026-06-02T00:00:00Z";\n'
        ),
    )
    assert compiled.policy is not None
    persist_node_policy(cacl_session, doc, compiled.policy)
    cacl_session.commit()

    before = datetime.datetime(2026, 5, 31, 23, 59, 59, tzinfo=datetime.UTC)
    start = datetime.datetime(2026, 6, 1, 0, 0, 0, tzinfo=datetime.UTC)
    end = datetime.datetime(2026, 6, 2, 0, 0, 0, tzinfo=datetime.UTC)

    d_before = authorize_node_operation(
        cacl_session, alice, doc, AtomicOp.READ_CONTENT, eval_time_utc=before
    )
    assert not d_before.allowed
    assert d_before.next_transition_at == start

    d_start = authorize_node_operation(
        cacl_session, alice, doc, AtomicOp.READ_CONTENT, eval_time_utc=start
    )
    assert d_start.allowed
    assert d_start.next_transition_at == end

    d_end = authorize_node_operation(
        cacl_session, alice, doc, AtomicOp.READ_CONTENT, eval_time_utc=end
    )
    assert not d_end.allowed
    assert d_end.next_transition_at is None


def test_authorize_dacl_save_detects_self_lockout(cacl_session):
    alice = models.User(
        username="alice",
        nickname="Alice",
        created_time=1.0,
        status=0,
        secret_key="s" * 64,
    )
    cacl_session.add(alice)
    cacl_session.flush()

    folder = models.Folder(id="f-lock", name="FLock", parent_id="/", inherit=False)
    cacl_session.add(folder)
    cacl_session.flush()

    initial = compile_policy_source(
        cacl_session,
        f'inherit off; allow [WRITE_DACL] to user("{alice.id}");',
    )
    assert initial.policy is not None
    persist_node_policy(cacl_session, folder, initial.policy)
    cacl_session.commit()

    lockout_policy = compile_policy_source(cacl_session, "inherit off;").policy
    assert lockout_policy is not None

    result = authorize_dacl_save(cacl_session, alice, folder, lockout_policy)
    assert result.authorized is True
    assert result.self_lockout_warning is True

    keep_policy = compile_policy_source(
        cacl_session, f'inherit off; allow [WRITE_DACL] to user("{alice.id}");'
    ).policy
    assert keep_policy is not None
    safe_result = authorize_dacl_save(cacl_session, alice, folder, keep_policy)
    assert safe_result.authorized is True
    assert safe_result.self_lockout_warning is False


def test_compile_strict_principals_reports_errors_with_spans(cacl_session):
    source = (
        'allow [READ_CONTENT] to user("00000000-0000-4000-8000-000000000001"),\n'
        '                       group("missing_group");\n'
    )
    strict = compile_policy_source(cacl_session, source, strict_principals=True)
    assert not strict.ok
    assert strict.policy is None
    by_code = {d.code: d for d in strict.errors}
    assert set(by_code) == {"E301", "E303"}

    assert by_code["E301"].span is not None
    assert by_code["E301"].span.line == 1

    assert by_code["E303"].span is not None
    assert by_code["E303"].span.line == 2


def test_would_self_lockout_on_create_and_bypass_dacl(cacl_session):
    alice = models.User(
        username="alice",
        nickname="Alice",
        created_time=1.0,
        status=0,
        secret_key="s" * 64,
    )
    cacl_session.add(alice)
    cacl_session.flush()

    parent = models.Folder(id="f-parent", name="Parent", parent_id="/", inherit=False)
    cacl_session.add(parent)
    cacl_session.flush()

    parent_policy = compile_policy_source(
        cacl_session,
        f'inherit off; allow [TRAVERSE, CREATE_DOCUMENT, WRITE_DACL] to user("{alice.id}");',
    ).policy
    assert parent_policy is not None
    persist_node_policy(cacl_session, parent, parent_policy)
    cacl_session.commit()

    lockout = compile_policy_source(cacl_session, "inherit off;").policy
    assert lockout is not None
    assert (
        would_self_lockout_on_create(
            cacl_session, alice, parent, ObjectType.DOCUMENT, "doc.txt", lockout
        )
        is True
    )

    safe = compile_policy_source(
        cacl_session,
        f'inherit off; allow [WRITE_DACL] to user("{alice.id}");',
    ).policy
    assert safe is not None
    assert (
        would_self_lockout_on_create(
            cacl_session, alice, parent, ObjectType.DOCUMENT, "doc.txt", safe
        )
        is False
    )

    admin = models.User(
        username="admin",
        nickname="Admin",
        created_time=1.0,
        status=0,
        secret_key="s" * 64,
    )
    admin.rights.append(
        models.UserPermission(
            permission=Permissions.BYPASS_DACL,
            granted=True,
            start_time=0.0,
            end_time=None,
        )
    )
    cacl_session.add(admin)
    cacl_session.flush()
    assert (
        would_self_lockout_on_create(
            cacl_session, admin, parent, ObjectType.DOCUMENT, "doc.txt", lockout
        )
        is False
    )


def test_utc_epoch_micros_roundtrip():
    ts = datetime.datetime(2026, 12, 1, 8, 30, 15, 123456, tzinfo=datetime.UTC)
    assert epoch_us_to_datetime(datetime_to_epoch_us(ts)) == ts


def test_compile_policy_source_enforces_rule_count_limit(cacl_session):
    lines = [
        f'allow [READ_METADATA] to group("g{i}");'
        for i in range(DACL_MAX_RULES_PER_NODE + 1)
    ]
    res = compile_policy_source(cacl_session, "\n".join(lines))
    assert not res.ok
    assert res.policy is None
    assert any(d.code == "E401" for d in res.errors)


def test_sql_regression_single_pass_and_expired_rule_filtering(cacl_session):
    alice = models.User(
        username="alice_sql",
        nickname="Alice",
        created_time=1.0,
        status=0,
        secret_key="s" * 64,
    )
    cacl_session.add(alice)
    cacl_session.flush()

    parent = models.Folder(id="sql-p", name="P", parent_id="/", inherit=True)
    cacl_session.add(parent)
    cacl_session.flush()
    child = models.Folder(id="sql-c", name="C", parent_id="sql-p", inherit=True)
    cacl_session.add(child)
    cacl_session.flush()
    leaf = models.Document(id="sql-d", title="D", folder_id="sql-c", inherit=True)
    cacl_session.add(leaf)
    cacl_session.flush()

    compiled = compile_policy_source(
        cacl_session,
        (
            "inherit on;\n"
            'allow [READ_DACL, DELETE] to any from "2020-01-01T00:00:00Z" until "2021-01-01T00:00:00Z";\n'
            'allow [READ_DACL, LIST_DIRECTORY, DELETE] to any from "2026-01-01T00:00:00Z" until "2027-01-01T00:00:00Z";\n'
        ),
    )
    assert compiled.policy is not None
    persist_node_policy(cacl_session, child, compiled.policy)
    cacl_session.commit()

    # Warm User cached_property permissions before counting authorization SQL.
    _ = alice.all_permissions
    _ = alice.all_groups

    engine = cacl_session.get_bind()
    statements: list[str] = []

    def _capture(_conn, _cursor, statement, _parameters, _context, _executemany):
        statements.append(statement)

    event.listen(engine, "before_cursor_execute", _capture)
    try:
        eval_now = datetime.datetime(2026, 6, 1, tzinfo=datetime.UTC)

        # 1. Directory access + visible parent_id uses only 1 CTE and no separate nodes.inherit query.
        statements.clear()
        allowed, visible_parent = authorize_directory_access_with_parent(
            cacl_session, alice, child, AtomicOp.LIST_DIRECTORY, eval_time_utc=eval_now
        )
        assert allowed is True
        assert visible_parent == parent.id
        cte_queries = [s for s in statements if "cacl_ancestor_chain" in s]
        assert len(cte_queries) == 1
        separate_inherit_queries = [
            s
            for s in statements
            if "SELECT nodes.id, nodes.inherit" in s and "cacl_ancestor_chain" not in s
        ]
        assert separate_inherit_queries == []

        # 2. DACL read uses only 1 CTE and still returns all rules (including expired rule).
        statements.clear()
        can_read, policy = authorize_dacl_read(
            cacl_session, alice, child, eval_time_utc=eval_now
        )
        assert can_read is True
        assert policy is not None
        assert len(policy.rules) == 2
        assert len([s for s in statements if "cacl_ancestor_chain" in s]) == 1

        # 3. Soft-delete root check + descendant check uses 0 ancestor CTEs for descendants.
        statements.clear()
        root_check = check_directory_soft_delete_root(
            cacl_session, alice, child, eval_time_utc=eval_now
        )
        assert root_check.allowed is True
        assert root_check.needs_descendant_check is True
        sub_folders, sub_docs = fetch_subtree_metadata_for_soft_delete(
            cacl_session, child.id
        )
        statements.clear()
        sub_decision = authorize_soft_delete_descendants(
            cacl_session, alice, child.id, [*sub_folders, *sub_docs], root_check
        )
        assert sub_decision.allowed is True
        assert [s for s in statements if "cacl_ancestor_chain" in s] == []
    finally:
        event.remove(engine, "before_cursor_execute", _capture)
