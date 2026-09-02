from pathlib import Path
from types import SimpleNamespace

import pytest
import tomlkit
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_SRC_PATH = _PROJECT_ROOT / "src"
_NOW = 1_700_000_000.0
_SYSOP_READ_RULES = {
    "read": [
        {
            "match": "all",
            "match_groups": [{"groups": {"match": "all", "require": ["sysop"]}}],
        }
    ]
}


@pytest.fixture()
def search_query_context(monkeypatch, tmp_path):
    config = tomlkit.parse((_SRC_PATH / "config.toml.sample").read_text("utf-8"))
    config["database"]["type"] = "sqlite"
    config["database"]["file"] = ":memory:"
    (tmp_path / "config.toml").write_text(tomlkit.dumps(config), encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    import include.database.models as models
    from include.database.session import Base
    from include.domains.access.authorization.access_rules import set_access_rules
    from include.domains.access.authorization.evaluation import (
        check_access_for_object,
    )
    from include.domains.access.authorization.searchable_tree import (
        load_folder_access_context,
    )
    from include.domains.documents.queries.listing import (
        fetch_visible_search_candidate_rows,
    )

    engine = create_engine("sqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    try:
        with session_factory() as session:
            session.add(models.Folder(id="/", name="/", inherit=False))
            session.commit()
            yield SimpleNamespace(
                check_access_for_object=check_access_for_object,
                fetch_visible_search_candidate_rows=fetch_visible_search_candidate_rows,
                load_folder_access_context=load_folder_access_context,
                models=models,
                session=session,
                set_access_rules=set_access_rules,
            )
    finally:
        engine.dispose()


def _make_user(context, *, permissions=(), username="alice"):
    user = context.models.User(
        username=username,
        pass_hash="hash",
        passwd_last_modified=_NOW,
        nickname=username,
        avatar_id=None,
        last_login=None,
        created_time=_NOW,
        status=0,
        secret_key=f"{username}-secret",
        totp_secret=None,
        totp_enabled=False,
        totp_backup_codes=None,
        preference_dek_id=None,
    )
    for permission in permissions:
        user.rights.append(
            context.models.UserPermission(
                username=username,
                permission=permission,
                granted=True,
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
    inherit: bool = True,
    access_rules: dict | None = None,
):
    folder = context.models.Folder(
        id=folder_id,
        name=name,
        parent_id=parent_id,
        inherit=inherit,
    )
    context.session.add(folder)
    context.session.flush()
    if access_rules is not None:
        context.set_access_rules(
            folder,
            access_rules,
            inherit_parent=inherit,
        )
    return folder


def test_visible_search_query_honors_oae_direct_grant(search_query_context):
    context = search_query_context
    user = _make_user(context)
    folder = _make_folder(
        context,
        "oae-visible",
        "SearchOAEVisible",
        access_rules=_SYSOP_READ_RULES,
    )
    context.session.add(
        context.models.ObjectAccessEntry(
            entity_type="user",
            entity_identifier=user.username,
            target_type="directory",
            target_identifier=folder.id,
            access_type="read",
            start_time=_NOW - 1,
            end_time=None,
        )
    )
    context.session.commit()

    rows = context.fetch_visible_search_candidate_rows(
        context.session,
        user=user,
        now=_NOW,
        query="SearchOAEVisible",
        sort_by="name",
        sort_order="asc",
        search_documents=False,
        search_directories=True,
        last_key=None,
        limit=10,
    )

    assert [item["id"] for item in rows] == [folder.id]


def test_visible_search_query_honors_compiled_rule_match_modes(
    search_query_context,
):
    context = search_query_context
    user = _make_user(context, permissions=["list_users"])
    query = "SearchCompiledRules"
    visible_rules = {
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
            },
            {
                "match": "all",
                "match_groups": [
                    {"rights": {"match": "all", "require": ["list_users"]}}
                ],
            },
        ]
    }
    hidden_rules = {
        "read": [
            {
                "match": "any",
                "match_groups": [
                    {
                        "rights": {
                            "match": "any",
                            "require": ["list_users"],
                        }
                    }
                ],
            },
            {
                "match": "all",
                "match_groups": [{"groups": {"match": "all", "require": ["sysop"]}}],
            },
        ]
    }
    visible_folder = _make_folder(
        context,
        "compiled-visible",
        f"{query}Visible",
        access_rules=visible_rules,
    )
    hidden_folder = _make_folder(
        context,
        "compiled-hidden",
        f"{query}Hidden",
        access_rules=hidden_rules,
    )
    context.session.commit()
    folders = [visible_folder, hidden_folder]

    ancestors, oaes = context.load_folder_access_context(
        context.session, folders, now=_NOW
    )
    python_visible_ids = {
        folder.id
        for folder in folders
        if context.check_access_for_object(
            folder,
            user,
            "read",
            ancestors,
            oaes,
            recursive=True,
        )
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

    assert sql_visible_ids == python_visible_ids == {visible_folder.id}


def test_visible_search_query_honors_inherit_false_boundary(search_query_context):
    context = search_query_context
    user = _make_user(context)
    query = "SearchInheritBoundary"
    parent = _make_folder(
        context,
        "inherit-parent",
        f"{query}Parent",
        access_rules=_SYSOP_READ_RULES,
    )
    child = _make_folder(
        context,
        "inherit-child",
        f"{query}Child",
        parent_id=parent.id,
        inherit=False,
    )
    context.session.commit()

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

    assert [item["id"] for item in rows] == [child.id]


def test_visible_search_query_honors_read_block(search_query_context):
    context = search_query_context
    user = _make_user(context)
    folder = _make_folder(
        context,
        "blocked-target",
        "SearchBlockedTarget",
    )
    block = context.models.UserBlockEntry(
        username=user.username,
        timestamp=_NOW,
        not_before=_NOW - 1,
        not_after=-1,
        target_type="directory",
        target_id=folder.id,
    )
    block.sub_entries.append(context.models.UserBlockSubEntry(block_type="read"))
    context.session.add(block)
    context.session.commit()

    rows = context.fetch_visible_search_candidate_rows(
        context.session,
        user=user,
        now=_NOW,
        query="SearchBlockedTarget",
        sort_by="name",
        sort_order="asc",
        search_documents=False,
        search_directories=True,
        last_key=None,
        limit=10,
    )

    assert rows == []


def test_visible_search_query_filters_before_limit(search_query_context):
    context = search_query_context
    user = _make_user(context)
    query = "SearchVisibilityLimit"
    for index in range(3):
        _make_folder(
            context,
            f"hidden-{index}",
            f"{query}Hidden{index}",
            access_rules=_SYSOP_READ_RULES,
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
