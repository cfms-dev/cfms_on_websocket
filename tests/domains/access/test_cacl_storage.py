"""Component tests for CACL storage, compilation, decompilation, and time-window evaluation."""

import datetime
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any, cast

import pytest
from cacl_compiler import AtomicOp, ObjectType
from sqlalchemy import event, select
from sqlalchemy.dialects import mysql, postgresql, sqlite
from sqlalchemy.orm import sessionmaker

from include.config.constants import DACL_MAX_RULES_PER_NODE
from include.database import models
from include.database.models.access import datetime_to_epoch_us, epoch_us_to_datetime
from include.database.models.documents import NodeType
from include.database.session import Base, Session
from include.domains.access.authorization import (
    evaluation as eval_mod,
)
from include.domains.access.authorization.engine import ObjectState
from include.domains.access.authorization.evaluation import (
    ListingMaskTarget,
    authorize_create_on_parent,
    authorize_dacl_read,
    authorize_directory_access,
    authorize_node_operation,
    authorize_soft_delete_descendants,
    authorize_write_dacl_and_load_path,
    check_directory_soft_delete_root,
    compute_listing_item_effective_masks,
    load_ancestor_paths_for_nodes,
    simulate_dacl_save_lockout,
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
from include.domains.documents.handlers.dacl import (
    NodeDaclTargetSpec,
    handle_set_node_dacl,
)
from include.domains.documents.queries.deletion_tree import (
    fetch_subtree_metadata_for_soft_delete,
)
from include.transport.connection import ConnectionHandler

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


def _make_user(
    username: str,
    *,
    nickname: str = "User",
    permissions: tuple[str, ...] = (),
) -> models.User:
    user = models.User(
        username=username,
        nickname=nickname,
        created_time=1.0,
        status=0,
        secret_key="s" * 64,
    )
    for perm in permissions:
        user.rights.append(
            models.UserPermission(
                permission=perm,
                granted=True,
                start_time=0.0,
                end_time=None,
            )
        )
    return user


def test_compile_persist_load_and_render_round_trip(cacl_session):
    alice = _make_user("alice", nickname="Alice")
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
    alice = _make_user("alice", nickname="Alice")
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


def test_authorize_write_dacl_and_simulate_lockout(cacl_session):
    alice = _make_user("alice", nickname="Alice")
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

    write_check = authorize_write_dacl_and_load_path(cacl_session, alice, folder)
    assert write_check.authorized is True
    assert write_check.current_path is not None

    lockout_policy = compile_policy_source(cacl_session, "inherit off;").policy
    assert lockout_policy is not None
    assert (
        simulate_dacl_save_lockout(
            alice,
            write_check.current_path,
            lockout_policy,
            check_ancestor_traverse=write_check.check_ancestor_traverse,
            eval_time_utc=write_check.eval_time_utc,
        )
        is True
    )

    keep_policy = compile_policy_source(
        cacl_session, f'inherit off; allow [WRITE_DACL] to user("{alice.id}");'
    ).policy
    assert keep_policy is not None
    assert (
        simulate_dacl_save_lockout(
            alice,
            write_check.current_path,
            keep_policy,
            check_ancestor_traverse=write_check.check_ancestor_traverse,
            eval_time_utc=write_check.eval_time_utc,
        )
        is False
    )

    bob = _make_user("bob_no_write", nickname="Bob")
    cacl_session.add(bob)
    cacl_session.flush()
    denied_check = authorize_write_dacl_and_load_path(cacl_session, bob, folder)
    assert denied_check.authorized is False
    assert denied_check.current_path is None


def test_write_dacl_enforces_step1_lifecycle_even_for_bypass_dacl(cacl_session):
    admin = _make_user(
        "admin_deleted_dacl",
        nickname="Admin",
        permissions=(Permissions.BYPASS_DACL,),
    )
    deleted_folder = models.Folder(
        id="f-deleted-dacl",
        name="DeletedFolder",
        parent_id="/",
        inherit=False,
        status=models.EntityStatus.DELETED,
    )
    deleted_doc = models.Document(
        id="d-deleted-dacl",
        title="DeletedDoc",
        folder_id="/",
        inherit=False,
        status=models.EntityStatus.DELETED,
    )
    active_folder = models.Folder(
        id="f-active-dacl",
        name="ActiveFolder",
        parent_id="/",
        inherit=False,
    )
    cacl_session.add_all([admin, deleted_folder, deleted_doc, active_folder])
    cacl_session.commit()

    assert (
        authorize_write_dacl_and_load_path(
            cacl_session, admin, deleted_folder
        ).authorized
        is False
    )
    assert (
        authorize_write_dacl_and_load_path(cacl_session, admin, deleted_doc).authorized
        is False
    )

    active_check = authorize_write_dacl_and_load_path(
        cacl_session, admin, active_folder
    )
    assert active_check.authorized is True
    assert active_check.current_path is None
    lockout_policy = compile_policy_source(cacl_session, "inherit off;").policy
    assert lockout_policy is not None
    assert (
        simulate_dacl_save_lockout(
            admin,
            active_check.current_path,
            lockout_policy,
            check_ancestor_traverse=active_check.check_ancestor_traverse,
            eval_time_utc=active_check.eval_time_utc,
        )
        is False
    )


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
    alice = _make_user("alice", nickname="Alice")
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

    admin = _make_user(
        "admin", nickname="Admin", permissions=(Permissions.BYPASS_DACL,)
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
    alice = _make_user("alice_sql", nickname="Alice")
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
        access = authorize_directory_access(
            cacl_session, alice, child, AtomicOp.LIST_DIRECTORY, eval_time_utc=eval_now
        )
        assert access.allowed is True
        assert access.visible_parent_id == parent.id
        assert access.effective_mask & int(AtomicOp.LIST_DIRECTORY)
        assert not (access.effective_mask & int(AtomicOp.READ_CONTENT))
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
        read_check = authorize_dacl_read(
            cacl_session, alice, child, eval_time_utc=eval_now
        )
        assert read_check.allowed is True
        assert read_check.policy is not None
        assert len(read_check.policy.rules) == 2
        assert read_check.effective_mask & int(AtomicOp.READ_DACL)
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


def test_load_node_policies_uses_single_join_query_and_preserves_fingerprint(
    cacl_session,
):
    alice = _make_user("alice_join", nickname="Alice")
    eng = models.UserGroup(group_name="eng_join", group_display_name="Engineering")
    cacl_session.add_all([alice, eng])
    cacl_session.flush()

    folder = models.Folder(id="join-f1", name="JoinF1", parent_id="/", inherit=False)
    cacl_session.add(folder)
    cacl_session.flush()

    source = (
        "inherit off;\n"
        "allow [TRAVERSE] to any;\n"
        f'allow [READ_CONTENT, READ_METADATA] on docs when (user("{alice.id}") or (group("eng_join") and not group("interns")));\n'
        f'deny [WRITE_CONTENT] on self to user("{alice.id}");\n'
    )
    compiled = compile_policy_source(cacl_session, source)
    assert compiled.policy is not None
    persist_node_policy(cacl_session, folder, compiled.policy)
    folder_id = folder.id
    cacl_session.commit()

    engine = cacl_session.get_bind()
    statements: list[str] = []

    def _capture(_conn, _cursor, statement, _parameters, _context, _executemany):
        statements.append(statement)

    event.listen(engine, "before_cursor_execute", _capture)
    try:
        loaded = load_node_policies(
            cacl_session,
            ["/", folder_id],
            preloaded_inherit={"/": False, folder_id: False},
            canonicalize=True,
        )
    finally:
        event.remove(engine, "before_cursor_execute", _capture)

    assert len(statements) == 1
    assert "dacl_rule_clauses" in statements[0]
    assert "dacl_rule_atoms" in statements[0]
    assert loaded[folder_id].fingerprint() == compiled.policy.fingerprint()
    assert len(loaded["/"].rules) == 2


def test_load_ancestor_paths_fails_closed_when_depth_limit_exceeded(
    cacl_session, monkeypatch
):
    parent_id = "/"
    deepest: models.Folder | None = None
    for idx in range(5):
        folder = models.Folder(
            id=f"deep-f-{idx}",
            name=f"Deep{idx}",
            parent_id=parent_id,
            inherit=True,
        )
        cacl_session.add(folder)
        cacl_session.flush()
        parent_id = folder.id
        deepest = folder
    cacl_session.commit()
    assert deepest is not None

    monkeypatch.setattr(eval_mod, "MAX_HIERARCHY_DEPTH", 2)
    with pytest.raises(RuntimeError, match="Incomplete ancestor chain"):
        load_ancestor_paths_for_nodes(cacl_session, [deepest])


def test_load_ancestor_paths_fails_closed_for_orphan_root_mismatch(cacl_session):
    orphan = models.Folder(
        id="orphan-unrooted",
        name="Orphan",
        parent_id=None,
        type=NodeType.DIRECTORY.value,
        status=models.EntityStatus.OK,
        inherit=True,
    )
    with pytest.raises(RuntimeError, match="not rooted at '/'"):
        load_ancestor_paths_for_nodes(cacl_session, [orphan])


def test_authorize_create_on_parent_checks_create_write_dacl_and_lifecycle(
    cacl_session,
):
    alice = _make_user("alice_create_check", nickname="Alice")
    create_only_dir = models.Folder(
        id="f-create-only", name="CreateOnly", parent_id="/", inherit=False
    )
    full_dir = models.Folder(
        id="f-create-full", name="CreateFull", parent_id="/", inherit=False
    )
    deleted_dir = models.Folder(
        id="f-create-deleted",
        name="CreateDeleted",
        parent_id="/",
        inherit=False,
        status=models.EntityStatus.DELETED,
    )
    cacl_session.add_all([alice, create_only_dir, full_dir, deleted_dir])
    cacl_session.flush()

    p_create_only = compile_policy_source(
        cacl_session, f'inherit off; allow [CREATE_DOCUMENT] to user("{alice.id}");'
    ).policy
    p_full = compile_policy_source(
        cacl_session,
        f'inherit off; allow [CREATE_DOCUMENT, WRITE_DACL] to user("{alice.id}");',
    ).policy
    assert p_create_only is not None
    assert p_full is not None
    persist_node_policy(cacl_session, create_only_dir, p_create_only)
    persist_node_policy(cacl_session, full_dir, p_full)
    persist_node_policy(cacl_session, deleted_dir, p_full)
    cacl_session.commit()

    check_only = authorize_create_on_parent(
        cacl_session,
        alice,
        create_only_dir,
        AtomicOp.CREATE_DOCUMENT,
        require_write_dacl=True,
    )
    assert check_only.can_create is True
    assert check_only.can_write_dacl is False

    check_full = authorize_create_on_parent(
        cacl_session,
        alice,
        full_dir,
        AtomicOp.CREATE_DOCUMENT,
        require_write_dacl=True,
    )
    assert check_full.can_create is True
    assert check_full.can_write_dacl is True

    check_deleted = authorize_create_on_parent(
        cacl_session,
        alice,
        deleted_dir,
        AtomicOp.CREATE_DOCUMENT,
        require_write_dacl=True,
    )
    assert check_deleted.can_create is False
    assert check_deleted.can_write_dacl is False


def test_load_node_policies_rejects_mutually_exclusive_time_refs(cacl_session):
    now = datetime.datetime(2026, 6, 1, tzinfo=datetime.UTC)
    with pytest.raises(ValueError, match="mutually exclusive"):
        load_node_policies(
            cacl_session,
            [],
            active_at_utc=now,
            exclude_expired_before=now,
        )


def test_soft_delete_root_check_directory_delete_child_bypass_and_missing_delete(
    cacl_session,
):
    alice = _make_user("alice_soft_delete_bypass", nickname="Alice")
    cacl_session.add(alice)
    cacl_session.flush()

    bypass_dir = models.Folder(id="sd-bypass", name="Bypass", parent_id="/")
    only_child_perm_dir = models.Folder(
        id="sd-only-child", name="OnlyChildPerm", parent_id="/"
    )
    cacl_session.add_all([bypass_dir, only_child_perm_dir])
    cacl_session.flush()
    denied_child = models.Document(
        id="sd-denied-child", title="DeniedChild", folder_id="sd-bypass"
    )
    cacl_session.add(denied_child)
    cacl_session.flush()

    bypass_policy = compile_policy_source(
        cacl_session,
        "inherit off; allow [TRAVERSE, DELETE, DIRECTORY_DELETE_CHILD] to any;",
    ).policy
    deny_policy = compile_policy_source(
        cacl_session, "inherit on; deny [DELETE] to any;"
    ).policy
    only_child_policy = compile_policy_source(
        cacl_session,
        "inherit off; allow [TRAVERSE, DIRECTORY_DELETE_CHILD] to any;",
    ).policy
    assert bypass_policy is not None
    assert deny_policy is not None
    assert only_child_policy is not None
    persist_node_policy(cacl_session, bypass_dir, bypass_policy)
    persist_node_policy(cacl_session, denied_child, deny_policy)
    persist_node_policy(cacl_session, only_child_perm_dir, only_child_policy)
    cacl_session.commit()

    root_bypass = check_directory_soft_delete_root(cacl_session, alice, bypass_dir)
    assert root_bypass.allowed is True
    assert root_bypass.needs_descendant_check is False
    sub_folders, sub_docs = fetch_subtree_metadata_for_soft_delete(
        cacl_session, bypass_dir.id
    )
    assert (
        authorize_soft_delete_descendants(
            cacl_session, alice, bypass_dir.id, [*sub_folders, *sub_docs], root_bypass
        ).allowed
        is True
    )

    root_only_child = check_directory_soft_delete_root(
        cacl_session, alice, only_child_perm_dir
    )
    assert root_only_child.allowed is False
    assert root_only_child.needs_descendant_check is False


_TEST_FOLDER_DACL_TARGET = NodeDaclTargetSpec(
    model_cls=models.Folder,
    target_type=ObjectType.DIRECTORY,
    not_found_message="not found",
    get_success_message="ok",
    set_success_message="ok",
)


class _RecordingDaclHandler:
    def __init__(self, user_id: str) -> None:
        self.user_id = user_id
        self.responses: list[tuple[int, dict[str, Any]]] = []

    def conclude_request(self, code: int, data: dict[str, Any], _message: str) -> None:
        self.responses.append((code, data))


@pytest.mark.parametrize("dialect_name", ["sqlite", "postgresql", "mysql"])
def test_dacl_locking_statements_compile_across_supported_dialects(dialect_name: str):
    dialect = {
        "sqlite": sqlite.dialect(),
        "postgresql": postgresql.dialect(),
        "mysql": mysql.dialect(),
    }[dialect_name]

    for model_cls in (models.Node, models.Folder, models.Document):
        compiled_sql = str(
            select(model_cls)
            .where(model_cls.id == "target-id")
            .with_for_update()
            .compile(dialect=dialect)
        )
        assert "nodes" in compiled_sql
        if dialect_name in ("postgresql", "mysql"):
            assert "FOR UPDATE" in compiled_sql


def test_handle_set_node_dacl_acquires_lock_before_reading_user_or_policy(
    sqlite_engine_factory, tmp_path
):
    engine = sqlite_engine_factory(tmp_path / "dacl_lock_order.db")
    Base.metadata.create_all(engine)

    with Session(bind=engine) as seed_session:
        root = models.Folder(id="/", name="/", inherit=False)
        seed_session.add(root)
        seed_session.flush()
        alice = _make_user("alice_lock_order", nickname="Alice")
        folder = models.Folder(
            id="f-lock-order", name="LockOrder", parent_id="/", inherit=False
        )
        seed_session.add_all([alice, folder])
        seed_session.flush()
        root_policy = compile_policy_source(
            seed_session, DEFAULT_ROOT_DACL_SOURCE
        ).policy
        folder_policy = compile_policy_source(
            seed_session,
            f'inherit off; allow [WRITE_DACL] to user("{alice.id}");',
        ).policy
        assert root_policy is not None
        assert folder_policy is not None
        persist_node_policy(seed_session, root, root_policy)
        persist_node_policy(seed_session, folder, folder_policy)
        alice_id = alice.id
        seed_session.commit()

    statements: list[str] = []

    def _capture(_conn, _cursor, statement, _parameters, _context, _executemany):
        statements.append(statement)

    event.listen(engine, "before_cursor_execute", _capture)
    try:
        recorder = _RecordingDaclHandler(alice_id)
        with Session(bind=engine) as session:
            result = handle_set_node_dacl(
                session,
                cast(ConnectionHandler, recorder),
                spec=_TEST_FOLDER_DACL_TARGET,
                target_id="f-lock-order",
                dacl_source=f'inherit off; allow [WRITE_DACL, READ_METADATA] to user("{alice_id}");',
                allow_self_lockout=False,
            )
    finally:
        event.remove(engine, "before_cursor_execute", _capture)

    assert result.code == 0
    assert len(recorder.responses) == 1
    assert recorder.responses[0][0] == 200
    assert statements[0] == "BEGIN IMMEDIATE"
    assert "folders" in statements[1]
    assert "users" not in statements[1]
    assert "cacl_ancestor_chain" not in statements[1]
    assert "dacl_rules" not in statements[1]


@pytest.mark.parametrize("concurrent_mutation", ["revoke_write_dacl", "soft_delete"])
def test_handle_set_node_dacl_serializes_concurrent_revocation_and_soft_delete(
    sqlite_engine_factory, tmp_path, concurrent_mutation: str
):
    engine = sqlite_engine_factory(
        tmp_path / f"dacl_race_{concurrent_mutation}.db", timeout_seconds=5
    )
    Base.metadata.create_all(engine)

    with Session(bind=engine) as seed_session:
        root = models.Folder(id="/", name="/", inherit=False)
        seed_session.add(root)
        seed_session.flush()
        alice = _make_user(f"alice_{concurrent_mutation}", nickname="Alice")
        folder = models.Folder(
            id="f-race", name="RaceFolder", parent_id="/", inherit=False
        )
        seed_session.add_all([alice, folder])
        seed_session.flush()
        root_policy = compile_policy_source(
            seed_session, DEFAULT_ROOT_DACL_SOURCE
        ).policy
        initial_policy = compile_policy_source(
            seed_session,
            f'inherit off; allow [WRITE_DACL] to user("{alice.id}");',
        ).policy
        assert root_policy is not None
        assert initial_policy is not None
        persist_node_policy(seed_session, root, root_policy)
        persist_node_policy(seed_session, folder, initial_policy)
        initial_fingerprint = initial_policy.fingerprint()
        alice_id = alice.id
        seed_session.commit()

    waiting = threading.Event()

    @event.listens_for(engine, "before_cursor_execute")
    def _observe_worker_lock(_conn, _cursor, statement, _params, _context, _many):
        if (
            threading.current_thread() is not threading.main_thread()
            and statement == "BEGIN IMMEDIATE"
        ):
            waiting.set()

    def _run_concurrent_dacl_set() -> tuple[int, int]:
        recorder = _RecordingDaclHandler(alice_id)
        with Session(bind=engine) as worker_session:
            result = handle_set_node_dacl(
                worker_session,
                cast(ConnectionHandler, recorder),
                spec=_TEST_FOLDER_DACL_TARGET,
                target_id="f-race",
                dacl_source=(
                    f'inherit off; allow [WRITE_DACL, LIST_DIRECTORY] to user("{alice_id}");'
                ),
                allow_self_lockout=False,
            )
            return result.code, recorder.responses[0][0]

    expected_fingerprint = initial_fingerprint
    try:
        with Session(bind=engine) as holder, ThreadPoolExecutor(max_workers=1) as pool:
            locked_folder = holder.get(
                models.Folder,
                "f-race",
                with_for_update=True,
                populate_existing=True,
            )
            assert locked_folder is not None
            if concurrent_mutation == "revoke_write_dacl":
                revoked_policy = compile_policy_source(
                    holder, "inherit off; allow [READ_METADATA] to any;"
                ).policy
                assert revoked_policy is not None
                persist_node_policy(holder, locked_folder, revoked_policy)
                expected_fingerprint = revoked_policy.fingerprint()
            else:
                locked_folder.status = models.EntityStatus.DELETED
                holder.flush()

            future = pool.submit(_run_concurrent_dacl_set)
            try:
                assert waiting.wait(3)
            finally:
                holder.commit()
            result_code, response_code = future.result(timeout=5)
    finally:
        event.remove(engine, "before_cursor_execute", _observe_worker_lock)

    expected_status = 403 if concurrent_mutation == "revoke_write_dacl" else 404
    assert result_code == expected_status
    assert response_code == expected_status

    with Session(bind=engine) as verify_session:
        persisted = load_node_policies(
            verify_session, ["f-race"], include_deleted=True
        )["f-race"]
        assert persisted.fingerprint() == expected_fingerprint


def test_listing_effective_masks_query_budgets_and_security_invariants(cacl_session):
    alice = _make_user("alice_listing_mask", nickname="Alice")
    bypass_no_global = _make_user(
        "bypass_no_global",
        nickname="BypassNoGlobal",
        permissions=(Permissions.BYPASS_DACL,),
    )
    bypass_with_global = _make_user(
        "bypass_with_global",
        nickname="BypassWithGlobal",
        permissions=(
            Permissions.BYPASS_DACL,
            Permissions.PURGE,
            Permissions.DELETE_REVISION,
        ),
    )
    traversable = models.Folder(id="f-trav", name="Traversable", parent_id="/")
    no_traverse = models.Folder(id="f-notrav", name="NoTraverse", parent_id="/")
    cacl_session.add_all(
        [alice, bypass_no_global, bypass_with_global, traversable, no_traverse]
    )
    cacl_session.flush()

    children_trav = [
        models.Folder(id="sub-inherit", name="SubInherit", parent_id=traversable.id),
        models.Folder(
            id="sub-custom",
            name="SubCustom",
            parent_id=traversable.id,
            inherit=False,
        ),
        models.Document(id="doc-inherit", title="DocInherit", folder_id=traversable.id),
        models.Document(
            id="doc-future",
            title="DocFuture",
            folder_id=traversable.id,
            inherit=False,
        ),
    ]
    child_blocked = models.Document(
        id="doc-under-notrav",
        title="DocUnderNoTrav",
        folder_id=no_traverse.id,
        inherit=False,
    )
    cacl_session.add_all([*children_trav, child_blocked])
    cacl_session.flush()

    for node, src in (
        (
            traversable,
            (
                "inherit off; "
                "allow [TRAVERSE, LIST_DIRECTORY, READ_CONTENT, READ_METADATA, DELETE_REVISION, PURGE] "
                f'to user("{alice.id}");'
            ),
        ),
        (
            no_traverse,
            f'inherit off; allow [LIST_DIRECTORY] to user("{alice.id}");',
        ),
        (
            children_trav[1],
            f'inherit off; allow [LIST_DIRECTORY, RENAME] to user("{alice.id}");',
        ),
        (
            children_trav[3],
            (
                "inherit off; "
                f'allow [READ_CONTENT] to user("{alice.id}") from "2026-07-01T00:00:00Z"; '
                f'allow [READ_METADATA] to user("{alice.id}") until "2026-05-01T00:00:00Z";'
            ),
        ),
        (
            child_blocked,
            f'inherit off; allow [READ_CONTENT, READ_METADATA] to user("{alice.id}");',
        ),
    ):
        compiled = compile_policy_source(cacl_session, src).policy
        assert compiled is not None
        persist_node_policy(cacl_session, node, compiled)
    cacl_session.commit()

    for u in (alice, bypass_no_global, bypass_with_global):
        _ = u.all_permissions
        _ = u.all_groups

    eval_now = datetime.datetime(2026, 6, 1, tzinfo=datetime.UTC)
    trav_targets = [
        ListingMaskTarget(
            "sub-inherit", ObjectType.DIRECTORY, ObjectState.NORMAL, True
        ),
        ListingMaskTarget(
            "sub-custom", ObjectType.DIRECTORY, ObjectState.NORMAL, False
        ),
        ListingMaskTarget("doc-inherit", ObjectType.DOCUMENT, ObjectState.NORMAL, True),
        ListingMaskTarget("doc-future", ObjectType.DOCUMENT, ObjectState.NORMAL, False),
    ]
    notrav_targets = [
        ListingMaskTarget(
            "doc-under-notrav", ObjectType.DOCUMENT, ObjectState.NORMAL, False
        ),
    ]

    access_trav = authorize_directory_access(
        cacl_session,
        alice,
        traversable,
        AtomicOp.LIST_DIRECTORY,
        eval_time_utc=eval_now,
    )
    access_notrav = authorize_directory_access(
        cacl_session,
        alice,
        no_traverse,
        AtomicOp.LIST_DIRECTORY,
        eval_time_utc=eval_now,
    )
    access_bypass_no = authorize_directory_access(
        cacl_session,
        bypass_no_global,
        traversable,
        AtomicOp.LIST_DIRECTORY,
        eval_time_utc=eval_now,
    )
    access_bypass_yes = authorize_directory_access(
        cacl_session,
        bypass_with_global,
        traversable,
        AtomicOp.LIST_DIRECTORY,
        eval_time_utc=eval_now,
    )

    engine = cacl_session.get_bind()
    statements: list[str] = []

    def _capture(_conn, _cursor, statement, _params, _context, _many):
        statements.append(statement)

    event.listen(engine, "before_cursor_execute", _capture)
    try:
        # 1. Normal user on traversable parent: exactly 1 dacl_rules query, 0 nodes/CTE queries.
        statements.clear()
        masks = compute_listing_item_effective_masks(
            cacl_session, alice, access_trav, trav_targets
        )
        assert len(statements) == 1
        assert "dacl_rules" in statements[0]
        assert "cacl_ancestor_chain" not in statements[0]
        assert masks["sub-inherit"] == int(
            AtomicOp.TRAVERSE | AtomicOp.LIST_DIRECTORY | AtomicOp.READ_METADATA
        )
        assert masks["sub-custom"] == int(AtomicOp.LIST_DIRECTORY | AtomicOp.RENAME)
        # DELETE_REVISION cleared because alice lacks global Permissions.DELETE_REVISION; PURGE cleared for NORMAL.
        assert masks["doc-inherit"] == int(
            AtomicOp.READ_CONTENT | AtomicOp.READ_METADATA
        )
        # Future & expired rules excluded at SQL level -> mask is 0.
        assert masks["doc-future"] == 0

        # 2. Parent lacking TRAVERSE -> 0 SQL queries and child masks forced to 0.
        statements.clear()
        blocked_masks = compute_listing_item_effective_masks(
            cacl_session, alice, access_notrav, notrav_targets
        )
        assert statements == []
        assert blocked_masks == {"doc-under-notrav": 0}

        # 3. BYPASS_DACL -> 0 SQL queries, still respects applicability and global gates.
        statements.clear()
        bypass_no_masks = compute_listing_item_effective_masks(
            cacl_session, bypass_no_global, access_bypass_no, trav_targets
        )
        assert statements == []
        assert not (bypass_no_masks["doc-inherit"] & int(AtomicOp.DELETE_REVISION))
        assert not (bypass_no_masks["doc-inherit"] & int(AtomicOp.PURGE))

        statements.clear()
        bypass_yes_masks = compute_listing_item_effective_masks(
            cacl_session, bypass_with_global, access_bypass_yes, trav_targets
        )
        assert statements == []
        assert bypass_yes_masks["doc-inherit"] & int(AtomicOp.DELETE_REVISION)
        assert not (bypass_yes_masks["doc-inherit"] & int(AtomicOp.PURGE))
    finally:
        event.remove(engine, "before_cursor_execute", _capture)
