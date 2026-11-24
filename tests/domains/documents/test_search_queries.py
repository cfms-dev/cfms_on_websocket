import datetime
import uuid
from types import SimpleNamespace

import pytest
from cacl_compiler import AtomicOp, CompiledPolicy, ObjectType, compile_cacl
from sqlalchemy import event
from sqlalchemy.orm import sessionmaker

from include.config.options import write_options
from include.database.cursors import (
    StreamingCursorBatchStrategy,
    WindowedKeysetBatchStrategy,
)
from include.database.models.documents import EntityStatus
from include.domains.access.authorization.engine import Subject
from include.domains.access.authorization.storage import AncestorNodeMeta
from include.domains.access.authorization.visibility import (
    BatchVisibilityEvaluator,
    VisibilityCandidate,
)
from include.domains.access.permissions import Permissions

_NOW_DT = datetime.datetime(2026, 6, 15, 12, 0, 0, tzinfo=datetime.UTC)
_NOW = _NOW_DT.timestamp()


@pytest.fixture
def search_query_context(sqlite_engine_factory):
    from include.database import models
    from include.database.session import Base
    from include.domains.access.authorization.evaluation import (
        authorize_node_operation,
    )
    from include.domains.access.authorization.storage import (
        DEFAULT_ROOT_DACL_SOURCE,
        compile_policy_source,
        persist_node_policy,
    )
    from include.domains.documents.queries.listing import (
        fetch_visible_search_candidate_rows,
    )

    engine = sqlite_engine_factory(":memory:")

    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    with session_factory() as session:
        root = models.Folder(id="/", name="/", inherit=False)
        session.add(root)
        session.flush()
        root_compiled = compile_policy_source(session, DEFAULT_ROOT_DACL_SOURCE)
        assert root_compiled.policy is not None
        persist_node_policy(session, root, root_compiled.policy)
        session.commit()
        yield SimpleNamespace(
            authorize_node_operation=authorize_node_operation,
            compile_policy_source=compile_policy_source,
            fetch_visible_search_candidate_rows=fetch_visible_search_candidate_rows,
            models=models,
            persist_node_policy=persist_node_policy,
            session=session,
        )


def _make_user(context, *, permissions=(), groups=(), username="alice"):
    user = context.models.User(
        username=username,
        nickname=username,
        avatar_id=None,
        last_login=None,
        created_time=_NOW,
        status=0,
        secret_key=f"{username}-secret",
        preference_dek_id=None,
    )
    for permission in permissions:
        user.rights.append(
            context.models.UserPermission(
                user=user,
                permission=permission,
                granted=True,
                start_time=0.0,
                end_time=None,
            )
        )
    for group_name in groups:
        if context.session.get(context.models.UserGroup, group_name) is None:
            context.session.add(
                context.models.UserGroup(
                    group_name=group_name,
                    group_display_name=group_name,
                )
            )
        user.groups.append(
            context.models.UserMembership(
                user=user,
                group_name=group_name,
                start_time=0.0,
                end_time=None,
            )
        )
    context.session.add(user)
    context.session.flush()
    return user


def _make_folder(
    context,
    folder_id: str,
    name: str,
    *,
    parent_id: str = "/",
    dacl: str | None = None,
):
    folder = context.models.Folder(
        id=folder_id,
        name=name,
        parent_id=parent_id,
        inherit=True,
    )
    context.session.add(folder)
    context.session.flush()
    if dacl is not None:
        compiled = context.compile_policy_source(context.session, dacl)
        assert not compiled.errors, compiled.diagnostics
        assert compiled.policy is not None
        context.persist_node_policy(context.session, folder, compiled.policy)
    return folder


def _make_document(
    context,
    doc_id: str,
    title: str,
    *,
    folder_id: str = "/",
    dacl: str | None = None,
):
    doc = context.models.Document(
        id=doc_id,
        title=title,
        folder_id=folder_id,
        inherit=True,
    )
    context.session.add(doc)
    context.session.flush()
    file_row = context.models.File(
        id=f"file-{doc_id}",
        path=f"/tmp/{doc_id}",
        sha256="a" * 64,
        active=True,
    )
    file_row.size = 12
    context.session.add(file_row)
    rev = context.models.DocumentRevision(
        id=f"rev-{doc_id}",
        document_id=doc.id,
        file_id=file_row.id,
        created_time=_NOW,
    )
    context.session.add(rev)
    context.session.flush()
    doc.current_revision_id = rev.id
    if dacl is not None:
        compiled = context.compile_policy_source(context.session, dacl)
        assert not compiled.errors, compiled.diagnostics
        assert compiled.policy is not None
        context.persist_node_policy(context.session, doc, compiled.policy)
    return doc


@pytest.mark.component
def test_visible_search_query_honors_cacl_dnf_and_negation(search_query_context):
    context = search_query_context
    alice = _make_user(context, groups=("engineering",), username="alice")
    bob = _make_user(context, groups=("engineering", "interns"), username="bob")
    query = "SearchDNF"

    visible_for_alice = _make_folder(
        context,
        "dnf-alice-only",
        f"{query}AliceOnly",
        dacl="""
            inherit off;
            allow [LIST_DIRECTORY] when (group("engineering") and not group("interns"));
        """,
    )
    explicit_user_folder = _make_folder(
        context,
        "dnf-user-grant",
        f"{query}UserGrant",
        dacl=f"""
            inherit off;
            allow [LIST_DIRECTORY] when (user("{alice.id}") or group("ops"));
        """,
    )
    context.session.commit()
    folders = [visible_for_alice, explicit_user_folder]

    for user, expected_ids in (
        (alice, {visible_for_alice.id, explicit_user_folder.id}),
        (bob, set()),
    ):
        python_visible_ids = {
            folder.id
            for folder in folders
            if context.authorize_node_operation(
                context.session,
                user,
                folder,
                AtomicOp.LIST_DIRECTORY,
                eval_time_utc=_NOW_DT,
            ).allowed
        }
        sql_visible_ids = {
            item["id"]
            for item in context.fetch_visible_search_candidate_rows(
                context.session,
                user=user,
                now=_NOW,
                query=query,
                sort_by="name",
                sort_order="asc",
                search_documents=False,
                search_directories=True,
                last_key=None,
                limit=10,
            )
        }
        assert sql_visible_ids == python_visible_ids == expected_ids


@pytest.mark.component
def test_visible_search_query_honors_inherit_off_and_ancestor_traverse(
    search_query_context,
):
    context = search_query_context
    user = _make_user(context, username="alice")
    query = "SearchTraverseBoundary"
    parent = _make_folder(
        context,
        "traverse-parent",
        f"{query}Parent",
        dacl="inherit off;",
    )
    child = _make_folder(
        context,
        "traverse-child",
        f"{query}Child",
        parent_id=parent.id,
        dacl="""
            inherit off;
            allow [LIST_DIRECTORY] to any;
        """,
    )
    context.session.commit()

    # Without TRAVERSE on parent, child is hidden even with inherit off + local allow.
    rows = context.fetch_visible_search_candidate_rows(
        context.session,
        user=user,
        now=_NOW,
        query=f"{query}Child",
        sort_by="name",
        sort_order="asc",
        search_documents=False,
        search_directories=True,
        last_key=None,
        limit=10,
    )
    assert rows == []

    # With global bypass_traverse_checking enabled, child becomes visible.
    write_options(
        context.session,
        "access",
        {"bypass_traverse_checking": True},
        expected_revisions={"bypass_traverse_checking": 0},
    )
    context.session.commit()

    rows_after = context.fetch_visible_search_candidate_rows(
        context.session,
        user=user,
        now=_NOW,
        query=f"{query}Child",
        sort_by="name",
        sort_order="asc",
        search_documents=False,
        search_directories=True,
        last_key=None,
        limit=10,
    )
    assert [item["id"] for item in rows_after] == [child.id]


@pytest.mark.component
def test_visible_search_query_honors_deny_overrides_and_time_windows(
    search_query_context,
):
    context = search_query_context
    user = _make_user(context, username="alice")
    denied_doc = _make_document(
        context,
        "denied-doc",
        "SearchWindowDenied",
        dacl=f"""
            allow [READ_CONTENT, READ_METADATA] to any;
            deny [READ_CONTENT, READ_METADATA] to user("{user.id}");
        """,
    )
    expired_doc = _make_document(
        context,
        "expired-doc",
        "SearchWindowExpired",
        dacl="""
            inherit off;
            allow [READ_METADATA] to any until "2026-06-15T12:00:00Z";
        """,
    )
    active_doc = _make_document(
        context,
        "active-doc",
        "SearchWindowActive",
        dacl="""
            inherit off;
            allow [READ_METADATA] to any from "2026-06-15T12:00:00Z" until "2026-06-15T13:00:00Z";
        """,
    )
    context.session.commit()

    rows = context.fetch_visible_search_candidate_rows(
        context.session,
        user=user,
        now=_NOW,
        query="SearchWindow",
        sort_by="name",
        sort_order="asc",
        search_documents=True,
        search_directories=False,
        last_key=None,
        limit=10,
    )
    assert [item["id"] for item in rows] == [active_doc.id]
    assert not context.authorize_node_operation(
        context.session, user, denied_doc, AtomicOp.READ_METADATA, eval_time_utc=_NOW_DT
    ).allowed
    assert not context.authorize_node_operation(
        context.session,
        user,
        expired_doc,
        AtomicOp.READ_METADATA,
        eval_time_utc=_NOW_DT,
    ).allowed


@pytest.mark.component
def test_visible_search_query_honors_scopes_and_bypass_dacl(search_query_context):
    context = search_query_context
    alice = _make_user(context, username="alice")
    admin = _make_user(
        context, permissions=(Permissions.BYPASS_DACL,), username="admin"
    )
    parent = _make_folder(
        context,
        "scope-parent",
        "SearchScopeParent",
        dacl="""
            inherit off;
            allow [TRAVERSE] to any;
            allow [READ_METADATA] on docs to any;
        """,
    )
    child_folder = _make_folder(
        context,
        "scope-child-folder",
        "SearchScopeChildFolder",
        parent_id=parent.id,
    )
    child_doc = _make_document(
        context,
        "scope-child-doc",
        "SearchScopeChildDoc",
        folder_id=parent.id,
    )
    context.session.commit()

    alice_rows = context.fetch_visible_search_candidate_rows(
        context.session,
        user=alice,
        now=_NOW,
        query="SearchScope",
        sort_by="name",
        sort_order="asc",
        search_documents=True,
        search_directories=True,
        last_key=None,
        limit=10,
    )
    assert [item["id"] for item in alice_rows] == [child_doc.id]

    admin_rows = context.fetch_visible_search_candidate_rows(
        context.session,
        user=admin,
        now=_NOW,
        query="SearchScope",
        sort_by="name",
        sort_order="asc",
        search_documents=True,
        search_directories=True,
        last_key=None,
        limit=10,
    )
    assert {item["id"] for item in admin_rows} == {
        parent.id,
        child_folder.id,
        child_doc.id,
    }


@pytest.mark.component
def test_visible_search_query_filters_before_limit(search_query_context):
    context = search_query_context
    user = _make_user(context)
    query = "SearchVisibilityLimit"
    for index in range(3):
        _make_folder(
            context,
            f"hidden-{index}",
            f"{query}Hidden{index}",
            dacl="inherit off;",
        )
    visible_folder = _make_folder(
        context,
        "visible-after-hidden",
        f"{query}Visible",
    )
    context.session.commit()

    rows = context.fetch_visible_search_candidate_rows(
        context.session,
        user=user,
        now=_NOW,
        query=query,
        sort_by="name",
        sort_order="asc",
        search_documents=False,
        search_directories=True,
        last_key=None,
        limit=1,
    )

    assert [item["id"] for item in rows] == [visible_folder.id]


@pytest.mark.component
def test_visible_search_query_multi_batch_pagination_and_no_legacy_ctes(
    search_query_context,
):
    context = search_query_context
    user = _make_user(context, username="alice_batch")
    query = "SearchBatchItem"

    # Create 150 hidden folders sorted before 5 visible folders (exceeds first batch of 128).
    for idx in range(150):
        _make_folder(
            context,
            f"batch-hidden-{idx:03d}",
            f"{query}A{idx:03d}",
            dacl="inherit off;",
        )
    expected_visible_ids: list[str] = []
    for idx in range(5):
        folder = _make_folder(
            context,
            f"batch-visible-{idx:03d}",
            f"{query}Z{idx:03d}",
        )
        expected_visible_ids.append(folder.id)
    context.session.commit()

    # Warm cached properties before listening to SQL.
    _ = user.all_permissions
    _ = user.all_groups

    engine = context.session.get_bind()
    statements: list[str] = []

    def _capture(_conn, _cursor, statement, _parameters, _context, _executemany):
        statements.append(statement)

    event.listen(engine, "before_cursor_execute", _capture)
    try:
        collected_ids: list[str] = []
        last_key = None
        while True:
            page = context.fetch_visible_search_candidate_rows(
                context.session,
                user=user,
                now=_NOW,
                query=query,
                sort_by="name",
                sort_order="asc",
                search_documents=False,
                search_directories=True,
                last_key=last_key,
                limit=2,
            )
            if not page:
                break
            collected_ids.extend(item["id"] for item in page)
            if len(page) < 2:
                break
            last_key = page[-1]["_cursor_key"]
    finally:
        event.remove(engine, "before_cursor_execute", _capture)

    assert collected_ids == expected_visible_ids
    for stmt in statements:
        assert "search_effective_chain" not in stmt
        assert "search_all_ancestors" not in stmt
        assert "search_anc_effective_chain" not in stmt


@pytest.mark.component
def test_visible_search_query_hides_items_under_soft_deleted_ancestor(
    search_query_context,
):
    context = search_query_context
    user = _make_user(context, username="alice_del_anc")
    parent = _make_folder(context, "del-anc-parent", "DeletedAncParent")
    child = _make_folder(
        context,
        "del-anc-child",
        "DeletedAncChildTarget",
        parent_id=parent.id,
    )
    parent.status = context.models.EntityStatus.DELETED
    context.session.commit()

    rows = context.fetch_visible_search_candidate_rows(
        context.session,
        user=user,
        now=_NOW,
        query="DeletedAncChildTarget",
        sort_by="name",
        sort_order="asc",
        search_documents=False,
        search_directories=True,
        last_key=None,
        limit=10,
    )
    assert rows == []

    write_options(
        context.session,
        "access",
        {"bypass_traverse_checking": True},
        expected_revisions={"bypass_traverse_checking": 0},
    )
    context.session.commit()

    rows_bypassed = context.fetch_visible_search_candidate_rows(
        context.session,
        user=user,
        now=_NOW,
        query="DeletedAncChildTarget",
        sort_by="name",
        sort_order="asc",
        search_documents=False,
        search_directories=True,
        last_key=None,
        limit=10,
    )
    assert [item["id"] for item in rows_bypassed] == [child.id]


@pytest.mark.component
def test_low_selectivity_document_search_avoids_repeated_revision_subquery_and_splits(
    search_query_context,
):
    context = search_query_context
    user = _make_user(context, username="alice_low_sel")
    query = "LowSelDoc"

    blocked_parent = _make_folder(
        context,
        "low-sel-blocked-parent",
        "BlockedParent",
        dacl="inherit off;",
    )
    # 400 docs hidden via blocked parent (traverse denied) + 250 docs hidden via own inherit off.
    for idx in range(400):
        doc = _make_document(
            context,
            f"ls-parent-hidden-{idx:03d}",
            f"{query}A{idx:03d}",
            folder_id=blocked_parent.id,
        )
        file_row = context.session.get(context.models.File, f"file-{doc.id}")
        assert file_row is not None
        file_row.size = 100 + idx
    for idx in range(250):
        doc = _make_document(
            context,
            f"ls-self-hidden-{idx:03d}",
            f"{query}B{idx:03d}",
            dacl="inherit off;",
        )
        file_row = context.session.get(context.models.File, f"file-{doc.id}")
        assert file_row is not None
        file_row.size = 1000 + idx

    expected_visible_ids: list[str] = []
    for idx in range(5):
        doc = _make_document(
            context,
            f"ls-visible-{idx:03d}",
            f"{query}Z{idx:03d}",
        )
        file_row = context.session.get(context.models.File, f"file-{doc.id}")
        assert file_row is not None
        file_row.size = 5000 + idx
        expected_visible_ids.append(doc.id)
    context.session.commit()

    _ = user.all_permissions
    _ = user.all_groups

    engine = context.session.get_bind()
    statements: list[str] = []

    def _capture(_conn, _cursor, statement, _parameters, _context, _executemany):
        statements.append(statement)

    event.listen(engine, "before_cursor_execute", _capture)
    try:
        # 1. Default sort_by="name": no search_current_chain / row_number at all,
        # and blocked parent pruning keeps total SQL count very low.
        statements.clear()
        name_rows = context.fetch_visible_search_candidate_rows(
            context.session,
            user=user,
            now=_NOW,
            query=query,
            sort_by="name",
            sort_order="asc",
            search_documents=True,
            search_directories=False,
            last_key=None,
            limit=5,
        )
        name_stmts = list(statements)

        # 2. sort_by="size": SQLite Phase 2 uses a single streaming cursor, so the
        # candidate query runs at most twice (Phase 1 probe + Phase 2 stream), and
        # no standalone clause/atom queries are emitted.
        statements.clear()
        size_rows = context.fetch_visible_search_candidate_rows(
            context.session,
            user=user,
            now=_NOW,
            query=query,
            sort_by="size",
            sort_order="asc",
            search_documents=True,
            search_directories=False,
            last_key=None,
            limit=5,
        )
        size_stmts = list(statements)
    finally:
        event.remove(engine, "before_cursor_execute", _capture)

    assert [item["id"] for item in name_rows] == expected_visible_ids
    assert [item["size"] for item in name_rows] == [5000, 5001, 5002, 5003, 5004]
    assert all("current_revision_id" not in item for item in name_rows)
    assert all("search_current_chain" not in stmt for stmt in name_stmts)
    assert all("row_number" not in stmt.lower() for stmt in name_stmts)
    assert not any(
        "FROM dacl_rule_clauses" in stmt or "FROM dacl_rule_atoms" in stmt
        for stmt in name_stmts
    )

    assert [item["id"] for item in size_rows] == expected_visible_ids
    assert [item["size"] for item in size_rows] == [5000, 5001, 5002, 5003, 5004]
    candidate_size_stmts = [stmt for stmt in size_stmts if "search_candidates" in stmt]
    assert len(candidate_size_stmts) <= 2
    assert not any(
        "FROM dacl_rule_clauses" in stmt or "FROM dacl_rule_atoms" in stmt
        for stmt in size_stmts
    )


@pytest.mark.component
@pytest.mark.parametrize("sort_by", ["name", "created_time", "size", "last_modified"])
@pytest.mark.parametrize("use_bypass", [False, True])
def test_search_active_revision_resolution_parity_across_sort_modes(
    search_query_context,
    sort_by: str,
    use_bypass: bool,
):
    context = search_query_context
    user = _make_user(
        context,
        permissions=(Permissions.BYPASS_DACL,) if use_bypass else (),
        username=f"rev_user_{sort_by}_{use_bypass}",
    )
    query = "RevParityDoc"

    # 1. Direct active current_revision
    doc_direct = context.models.Document(
        id="rev-direct", title=f"{query}1Direct", folder_id="/", created_time=_NOW + 1
    )
    f_direct = context.models.File(
        id="f-rev-direct", path="/tmp/direct", sha256="a" * 64, active=True
    )
    f_direct.size = 300
    r_direct = context.models.DocumentRevision(
        id="r-rev-direct",
        document_id=doc_direct.id,
        file_id=f_direct.id,
        created_time=_NOW + 10,
    )
    context.session.add_all([doc_direct, f_direct, r_direct])
    context.session.flush()
    doc_direct.current_revision_id = r_direct.id

    # 2. Inactive current_revision falling back along parent_revision_id chain
    doc_chain = context.models.Document(
        id="rev-chain", title=f"{query}2Chain", folder_id="/", created_time=_NOW + 2
    )
    f_chain_old = context.models.File(
        id="f-chain-old", path="/tmp/chain-old", sha256="b" * 64, active=True
    )
    f_chain_old.size = 100
    f_chain_new = context.models.File(
        id="f-chain-new", path="/tmp/chain-new", sha256="c" * 64, active=False
    )
    f_chain_new.size = 999
    r_chain_old = context.models.DocumentRevision(
        id="r-chain-old",
        document_id=doc_chain.id,
        file_id=f_chain_old.id,
        created_time=_NOW + 30,
    )
    r_chain_new = context.models.DocumentRevision(
        id="r-chain-new",
        document_id=doc_chain.id,
        file_id=f_chain_new.id,
        parent_revision_id=r_chain_old.id,
        created_time=_NOW + 40,
    )
    context.session.add_all(
        [doc_chain, f_chain_old, f_chain_new, r_chain_old, r_chain_new]
    )
    context.session.flush()
    doc_chain.current_revision_id = r_chain_new.id

    # 3. current_revision_id is None -> fallback to latest active revision by created_time
    doc_fallback = context.models.Document(
        id="rev-fallback",
        title=f"{query}3Fallback",
        folder_id="/",
        created_time=_NOW + 3,
    )
    f_fb_1 = context.models.File(
        id="f-fb-1", path="/tmp/fb1", sha256="d" * 64, active=True
    )
    f_fb_1.size = 150
    f_fb_2 = context.models.File(
        id="f-fb-2", path="/tmp/fb2", sha256="e" * 64, active=True
    )
    f_fb_2.size = 200
    r_fb_1 = context.models.DocumentRevision(
        id="r-fb-1",
        document_id=doc_fallback.id,
        file_id=f_fb_1.id,
        created_time=_NOW + 5,
    )
    r_fb_2 = context.models.DocumentRevision(
        id="r-fb-2",
        document_id=doc_fallback.id,
        file_id=f_fb_2.id,
        created_time=_NOW + 20,
    )
    context.session.add_all([doc_fallback, f_fb_1, f_fb_2, r_fb_1, r_fb_2])
    context.session.flush()
    doc_fallback.current_revision_id = None

    # 4. Document with NO active revision (must be excluded without shortening limit)
    doc_inactive = context.models.Document(
        id="rev-inactive",
        title=f"{query}0Inactive",
        folder_id="/",
        created_time=_NOW,
    )
    f_inactive = context.models.File(
        id="f-inactive", path="/tmp/inactive", sha256="f" * 64, active=False
    )
    f_inactive.size = 50
    r_inactive = context.models.DocumentRevision(
        id="r-inactive",
        document_id=doc_inactive.id,
        file_id=f_inactive.id,
        created_time=_NOW + 1,
    )
    context.session.add_all([doc_inactive, f_inactive, r_inactive])
    context.session.flush()
    doc_inactive.current_revision_id = r_inactive.id
    context.session.commit()

    rows = context.fetch_visible_search_candidate_rows(
        context.session,
        user=user,
        now=_NOW,
        query=query,
        sort_by=sort_by,
        sort_order="asc",
        search_documents=True,
        search_directories=False,
        last_key=None,
        limit=3,
    )

    by_id = {row["id"]: (row["last_modified"], row["size"]) for row in rows}
    assert by_id == {
        "rev-direct": (_NOW + 10, 300),
        "rev-chain": (_NOW + 30, 100),
        "rev-fallback": (_NOW + 20, 200),
    }

    expected_order = {
        "name": ["rev-direct", "rev-chain", "rev-fallback"],
        "created_time": ["rev-direct", "rev-chain", "rev-fallback"],
        "size": ["rev-chain", "rev-fallback", "rev-direct"],
        "last_modified": ["rev-direct", "rev-fallback", "rev-chain"],
    }[sort_by]
    assert [row["id"] for row in rows] == expected_order


@pytest.mark.unit
@pytest.mark.parametrize("dialect_name", ["sqlite", "postgresql", "mysql"])
def test_search_statements_compile_across_supported_dialects(dialect_name: str):
    from sqlalchemy.dialects import mysql, postgresql, sqlite

    from include.domains.access.authorization.storage import (
        build_ancestors_and_active_policies_stmt,
    )
    from include.domains.documents.queries.listing import (
        _build_search_select,
        _search_candidate_selectable,
        _search_lightweight_candidate_selectable,
        _search_primary_column,
    )

    dialect = {
        "sqlite": sqlite.dialect(),
        "postgresql": postgresql.dialect(),
        "mysql": mysql.dialect(),
    }[dialect_name]

    lightweight = _search_lightweight_candidate_selectable(
        query="demo",
        search_documents=True,
        search_directories=True,
        require_active_document_revision=False,
    )
    assert lightweight is not None
    lw_sql = str(
        _build_search_select(
            lightweight,
            _search_primary_column(lightweight, "name"),
            ["a", 0, "id-1"],
            "asc",
            include_revision_details=False,
            limit=128,
        ).compile(dialect=dialect)
    )
    assert "search_candidates" in lw_sql

    full = _search_candidate_selectable(
        query="demo",
        search_documents=True,
        search_directories=True,
    )
    assert full is not None
    full_sql = str(
        _build_search_select(
            full,
            _search_primary_column(full, "size"),
            [100, 1, "id-1"],
            "desc",
            include_revision_details=True,
            limit=128,
        ).compile(dialect=dialect)
    )
    assert "matched_documents" in full_sql
    assert "search_current_chain" in full_sql

    combined_sql = str(
        build_ancestors_and_active_policies_stmt(
            ["folder-1"], ["doc-1", "doc-2"], _NOW_DT
        ).compile(dialect=dialect)
    )
    assert "search_anc_meta" in combined_sql
    assert "dacl_rule_atoms" in combined_sql


@pytest.mark.component
def test_windowed_keyset_batch_strategy_matches_streaming_parity(search_query_context):
    context = search_query_context
    user = _make_user(context, username="alice_windowed")
    query = "WindowParity"

    for idx in range(180):
        _make_folder(
            context,
            f"wp-hidden-{idx:03d}",
            f"{query}A{idx:03d}",
            dacl="inherit off;",
        )
    expected_visible_ids: list[str] = []
    for idx in range(6):
        folder = _make_folder(
            context,
            f"wp-visible-{idx:03d}",
            f"{query}Z{idx:03d}",
        )
        expected_visible_ids.append(folder.id)
    context.session.commit()

    def _collect_all(strategy):
        collected: list[str] = []
        last_key = None
        while True:
            page = context.fetch_visible_search_candidate_rows(
                context.session,
                user=user,
                now=_NOW,
                query=query,
                sort_by="name",
                sort_order="asc",
                search_documents=False,
                search_directories=True,
                last_key=last_key,
                limit=2,
                batch_strategy=strategy,
            )
            if not page:
                break
            collected.extend(item["id"] for item in page)
            if len(page) < 2:
                break
            last_key = page[-1]["_cursor_key"]
        return collected

    streaming_ids = _collect_all(StreamingCursorBatchStrategy(chunk_size=16))
    windowed_ids = _collect_all(WindowedKeysetBatchStrategy(window_sizes=(20, 40)))
    assert streaming_ids == expected_visible_ids
    assert windowed_ids == expected_visible_ids


@pytest.mark.component
def test_windowed_keyset_batch_strategy_matches_streaming_for_document_size_desc(
    search_query_context,
):
    context = search_query_context
    user = _make_user(context, username="alice_windowed_docs")
    query = "WindowDocSize"

    for idx in range(180):
        doc = _make_document(
            context,
            f"wds-hidden-{idx:03d}",
            f"{query}Hidden{idx:03d}",
            dacl="inherit off;",
        )
        file_row = context.session.get(context.models.File, f"file-{doc.id}")
        assert file_row is not None
        file_row.size = 10_000 + idx

    visible_docs: list[tuple[str, int]] = []
    for idx in range(6):
        doc = _make_document(
            context,
            f"wds-visible-{idx:03d}",
            f"{query}Visible{idx:03d}",
        )
        file_row = context.session.get(context.models.File, f"file-{doc.id}")
        assert file_row is not None
        size = 500 + idx * 10
        file_row.size = size
        visible_docs.append((doc.id, size))
    context.session.commit()

    expected_visible = list(reversed(visible_docs))

    def _collect_all(strategy):
        collected: list[tuple[str, int]] = []
        last_key = None
        while True:
            page = context.fetch_visible_search_candidate_rows(
                context.session,
                user=user,
                now=_NOW,
                query=query,
                sort_by="size",
                sort_order="desc",
                search_documents=True,
                search_directories=False,
                last_key=last_key,
                limit=2,
                batch_strategy=strategy,
            )
            if not page:
                break
            collected.extend((item["id"], item["size"]) for item in page)
            if len(page) < 2:
                break
            last_key = page[-1]["_cursor_key"]
        return collected

    streaming_rows = _collect_all(StreamingCursorBatchStrategy(chunk_size=16))
    windowed_rows = _collect_all(WindowedKeysetBatchStrategy(window_sizes=(20, 40)))
    assert streaming_rows == expected_visible
    assert windowed_rows == expected_visible


@pytest.mark.component
def test_search_visibility_fails_closed_when_ancestor_chain_truncated(
    search_query_context, monkeypatch
):
    from include.domains.access.authorization import storage as storage_mod

    context = search_query_context
    user = _make_user(context, username="alice_deep_search")

    parent_id = "/"
    for idx in range(5):
        folder = _make_folder(
            context,
            f"deep-search-{idx}",
            f"DeepSearchDir{idx}",
            parent_id=parent_id,
        )
        parent_id = folder.id
    _make_document(
        context,
        "deep-search-doc",
        "DeepSearchTargetDoc",
        folder_id=parent_id,
    )
    context.session.commit()

    monkeypatch.setattr(storage_mod, "MAX_HIERARCHY_DEPTH", 2)

    # Fails closed with normal traverse checking.
    rows = context.fetch_visible_search_candidate_rows(
        context.session,
        user=user,
        now=_NOW,
        query="DeepSearchTargetDoc",
        sort_by="name",
        sort_order="asc",
        search_documents=True,
        search_directories=False,
        last_key=None,
        limit=10,
    )
    assert rows == []

    # Still fails closed even when bypass_traverse_checking is enabled.
    write_options(
        context.session,
        "access",
        {"bypass_traverse_checking": True},
        expected_revisions={"bypass_traverse_checking": 0},
    )
    context.session.commit()

    rows_bypassed = context.fetch_visible_search_candidate_rows(
        context.session,
        user=user,
        now=_NOW,
        query="DeepSearchTargetDoc",
        sort_by="name",
        sort_order="asc",
        search_documents=True,
        search_directories=False,
        last_key=None,
        limit=10,
    )
    assert rows_bypassed == []


@pytest.mark.unit
def test_batch_visibility_evaluator_fails_closed_for_orphan_ancestor():
    evaluator = BatchVisibilityEvaluator(
        session=None,  # type: ignore[arg-type]
        subject=Subject(user_id=uuid.uuid4()),
        now_utc=_NOW_DT,
        check_traverse=False,
    )
    evaluator._node_meta["orphan-dir"] = AncestorNodeMeta(
        parent_id=None,
        status=EntityStatus.OK.value,
        inherit=False,
    )
    allow_read = compile_cacl("inherit off; allow [READ_CONTENT] to any;").policy
    assert allow_read is not None
    evaluator._node_policies["orphan-dir"] = CompiledPolicy(inherit=False, rules=())
    evaluator._node_policies["child-doc"] = allow_read

    candidate = VisibilityCandidate(
        node_id="child-doc",
        parent_id="orphan-dir",
        object_type=ObjectType.DOCUMENT,
        inherit=False,
    )
    assert evaluator.is_visible(candidate) is False
